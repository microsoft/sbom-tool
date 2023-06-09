using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Processors;
internal class FilesProcessor : IProcessor
{
    private readonly IEnumerable<ISourceProvider> sourceProviders;
    private readonly ILogger logger;

    public FilesProcessor(IEnumerable<ISourceProvider> sourceProviders, ILogger logger)
    {
        this.sourceProviders = sourceProviders;
        this.logger = logger;
    }

    public async Task ProcessAsync(ChannelWriter<Element> serializerChannel, ChannelWriter<ErrorInfo> errorsChannel)
    {
        try
        {
            foreach (var sourceProvider in sourceProviders)
            {
                await foreach (var file in sourceProvider.Get())
                {
                    if (file is FileElement fileElement)
                    {
                        var sbomFile = new Spdx3_0.Software.File(fileElement.Path)
                        {
                            verifiedUsing = ConvertToSpdxIntegrityMethods(fileElement.Hashes),
                        };
                        await serializerChannel.WriteAsync(sbomFile);
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
