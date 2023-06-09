using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Core.Enums;
using Microsoft.Sbom.Utils;

namespace Microsoft.Sbom;
internal class SoftwareProfileOrchestrator
{
    private readonly Configuration? configuration;
    private readonly IList<IProcessor> processors;
    private readonly IList<ISourceProvider> sourceProviders;
    private readonly ISerializer serializer;
    private readonly ILogger logger;
    private readonly IdentifierUtils identifierUtils;

    public SoftwareProfileOrchestrator(Configuration configuration, IList<IProcessor> processors, IList<ISourceProvider> sourceProviders, ISerializer serializer, ILogger logger)
    {
        this.configuration = configuration;
        this.processors = processors;
        this.sourceProviders = sourceProviders;
        this.serializer = serializer;
        this.logger = logger;
        this.identifierUtils = new IdentifierUtils(configuration);
    }

    internal async Task RunAsync()
    {
        var serializerChannel = Channel.CreateUnbounded<Element>();
        var errorsChannel = Channel.CreateUnbounded<ErrorInfo>();
        var identifiersChannel = Channel.CreateUnbounded<Uri>();

        using var _ = serializer;
        try
        {
            serializer.Start();

            var creator = await GetCreator();
            await serializerChannel.Writer.WriteAsync(creator);

            // Start processing in a separate task
            var processingTask = Task.Run(async () =>
            {
                foreach (var processor in processors)
                {
                    await processor.ProcessAsync(serializerChannel.Writer, errorsChannel.Writer, identifiersChannel.Writer);
                }

                identifiersChannel.Writer.Complete();
            });

            var relationshipsTask = Task.Run(async () =>
            {
                var ids = new List<Element>();
                await foreach (var id in identifiersChannel.Reader.ReadAllAsync())
                {
                    ids.Add(new Identifier(id));
                }

                // Add the BOM to the graph.
                await serializerChannel.Writer.WriteAsync(new Bom(Constants.SBOMName)
                {
                    elements = ids,
                    creationInfo = Constants.CreationInfoId,
                    spdxId = identifierUtils.GetSbomId(),
                });

                // Add SPDX document to the graph.
                // SPDX document references itself?? thats how spdx designed serialization.
                var documentId = identifierUtils.GetSpdxDocumentId();
                ids.Add(new Identifier(documentId));
                ids.Add(new Identifier(creator.spdxId));

                await serializerChannel.Writer.WriteAsync(new SpdxDocument(configuration?.Name ?? Constants.DefaultDocumentName)
                {
                    elements = ids,
                    creationInfo = Constants.CreationInfoId,
                    spdxId = documentId,
                });

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
            await Task.WhenAll(processingTask, relationshipsTask, serializationTask, errorLoggingTask);
        }
        finally
        {
            serializer.EndDocument();
        }
    }

    private async Task<Person> GetCreator()
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
                spdxId = Constants.CreationInfoId,
                specVersion = Constants.SpecVersion,
                created = DateTime.UtcNow,
                profile = new List<ProfileIdentifierType> { ProfileIdentifierType.Core, ProfileIdentifierType.Software },
                dataLicense = Constants.DataLicense,
            },
            name = userInfo?.userName,
            externalIdentifiers = externalIdentifiers,
            spdxId = identifierUtils.GetPersonId(),
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