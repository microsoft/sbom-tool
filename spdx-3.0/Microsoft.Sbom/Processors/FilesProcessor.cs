using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Utils;

namespace Microsoft.Sbom.Processors;
internal class FilesProcessor : IProcessor
{
    private readonly Configuration configuration;
    private readonly IEnumerable<ISourceProvider> sourceProviders;
    private readonly ILogger logger;
    private readonly IdentifierUtils identifierUtils;

    public FilesProcessor(Configuration configuration, IEnumerable<ISourceProvider> sourceProviders, ILogger logger)
    {
        this.configuration = configuration;
        this.sourceProviders = sourceProviders;
        this.logger = logger;
        this.identifierUtils = new IdentifierUtils(configuration);
    }

    public async Task ProcessAsync(ChannelWriter<Element> serializerChannel, ChannelWriter<ErrorInfo> errorsChannel, ChannelWriter<Uri> identifierChannel)
    {
        try
        {
            foreach (var sourceProvider in sourceProviders)
            {
                await foreach (var file in sourceProvider.Get())
                {
                    if (file is FileElement fileElement)
                    {
                        var id = identifierUtils.GetFileId();
                        var sbomFile = new Spdx3_0.Software.File(fileElement.Path)
                        {
                            spdxId = id,
                            verifiedUsing = ConvertToSpdxIntegrityMethods(fileElement.Hashes),
                        };
                        await serializerChannel.WriteAsync(sbomFile);
                        await identifierChannel.WriteAsync(id);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            errorsChannel.TryWrite(new ErrorInfo(nameof(FilesProcessor), ex, string.Empty));
        }
    }

    private IList<IntegrityMethod>? ConvertToSpdxIntegrityMethods(IList<FileHash>? hashes)
    {
        if (hashes == null)
        {
            return null;
        }

        var integrityMethods = new List<IntegrityMethod>();
        foreach (var hash in hashes)
        {
            if (Enum.TryParse<Spdx3_0.Core.Enums.HashAlgorithm>(hash.Algorithm, out var algorithm))
            {
                integrityMethods.Add(new Hash(algorithm, hash.Value));
            }
        }

        return integrityMethods;
    }
}
