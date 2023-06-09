using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom;
internal class SoftwareProfileOrchestrator
{
    private readonly string documentName;
    private readonly IList<IProcessor> processors;
    private readonly IList<ISourceProvider> sourceProviders;
    private readonly ISerializer serializer;
    private readonly ILogger logger;

    public SoftwareProfileOrchestrator(string documentName, IList<IProcessor> processors, IList<ISourceProvider> sourceProviders, ISerializer serializer, ILogger logger)
    {
        this.documentName = documentName;
        this.processors = processors;
        this.sourceProviders = sourceProviders;
        this.serializer = serializer;
        this.logger = logger;
    }

    internal async Task RunAsync()
    {
        var serializerChannel = Channel.CreateUnbounded<Element>();
        var errorsChannel = Channel.CreateUnbounded<ErrorInfo>();

        using var _ = serializer;
        try
        {
            serializer.Start();

            await serializerChannel.Writer.WriteAsync(await GetPerson());

            new SpdxDocument(documentName);

            // Start processing in a separate task
            var processingTask = Task.Run(async () =>
            {
                foreach (var processor in processors)
                {
                    await processor.ProcessAsync(serializerChannel.Writer, errorsChannel.Writer);
                }

                // Mark the channels as complete when all processing is done
                serializerChannel.Writer.Complete();
                errorsChannel.Writer.Complete();
            });

            // Start reading and serializing in parallel with processing
            var serializationTask = Task.Run(async () =>
            {
                await foreach (var element in serializerChannel.Reader.ReadAllAsync())
                {
                    serializer.Serialize(element, element.GetType());
                }
            });

            // Start logging errors in parallel with processing
            var errorLoggingTask = Task.Run(async () =>
            {
                await foreach (var errorInfo in errorsChannel.Reader.ReadAllAsync())
                {
                    logger.LogError(errorInfo.Exception, "Error in {className}: {exceptionMessage}. Additional message: {additionalMessage}", errorInfo.ClassName, errorInfo.Exception.Message, errorInfo.Message);
                }
            });

            // Wait for all tasks to complete
            await Task.WhenAll(processingTask, serializationTask, errorLoggingTask);
        }
        finally
        {
            serializer.EndDocument();
        }
    }

    private async Task<Person> GetPerson()
    {
        var userInfo = await GetUserInfo();
        IList<ExternalIdentifier>? externalIdentifiers = null;
        if (!string.IsNullOrEmpty(userInfo?.userEmail))
        {
            externalIdentifiers = new List<ExternalIdentifier>
            {
                new ExternalIdentifier(ExternalIdentifierType.Email, userInfo?.userEmail)
            };
        }

        return new Person
        {
            creationInfo = new CreationInfo
            {
                specVersion = Constants.SpecVersion,
                created = DateTime.UtcNow,
                profile = new List<ProfileIdentifierType> { ProfileIdentifierType.Core, ProfileIdentifierType.Software },
                dataLicense = Constants.DataLicense,
            },
            name = userInfo?.userName,
            externalIdentifiers = externalIdentifiers
        };
    }

    private async Task<UserInfo?> GetUserInfo()
    {
        UserInfo? bestUserInfo = default;
        foreach (var userInfoProvider in sourceProviders.Where(s => s.SourceType == Enums.SourceType.UserInfo))
        {
            await foreach (var providerObject in userInfoProvider.Get())
            {
                if (providerObject is UserInfo userInfo)
                {
                    if (!string.IsNullOrWhiteSpace(userInfo.userName) && !string.IsNullOrWhiteSpace(userInfo.userEmail))
                    {
                        // This user info has both fields, so it's the best possible match.
                        // We return it immediately.
                        return userInfo;
                    }

                    if (bestUserInfo == null
                        && (!string.IsNullOrWhiteSpace(userInfo.userName) || !string.IsNullOrWhiteSpace(userInfo.userEmail)))
                    {
                        // This user info has at least one field and it's better than what we have so far.
                        bestUserInfo = userInfo;
                    }
                }
            }   
        }

        return bestUserInfo;
    }
}