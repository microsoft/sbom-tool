using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Processors;
internal class PackagesProcessor : IProcessor
{
    private readonly IEnumerable<ISourceProvider> sourceProviders;
    private readonly ILogger logger;

    public PackagesProcessor(IEnumerable<ISourceProvider> sourceProviders, ILogger logger)
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
                await foreach (var package in sourceProvider.Get())
                {
                    await serializerChannel.WriteAsync(package);
                }
            }
        }
        catch (Exception ex)
        {
            errorsChannel.TryWrite(new ErrorInfo(nameof(PackagesProcessor), ex, string.Empty));
        }
    }
}
