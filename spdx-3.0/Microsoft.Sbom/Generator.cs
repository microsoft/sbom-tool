using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.File;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.JsonSerializer;
using Microsoft.Sbom.Processors;

namespace Microsoft.Sbom;
public class Generator
{
    private readonly IList<ISourceProvider> sourceProviders;
    private readonly ISerializer serializer;
    private readonly ILogger logger;
    private readonly IList<IProcessor> processors;

    public Generator(IList<ISourceProvider>? sourceProviders = null, ISerializer? serializer = null, ILogger? logger = null)
    {
        this.logger = logger ?? NullLogger.Instance;
        this.sourceProviders = sourceProviders ?? new List<ISourceProvider>() { new FileSourceProvider(logger: logger) };
        
        var filePath = Path.Combine(Path.GetTempPath(), $"sbom-{Guid.NewGuid()}.json");
        this.logger.LogDebug("Writing SBOM to {filePath}", filePath);
        this.serializer = serializer ?? new Spdx3JsonSerializer(filePath, this.logger);
        this.processors = new List<IProcessor>()
        {
            new FilesProcessor(this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Files), this.logger),
        };
    }

    public async Task GenerateSBOM()
    {
        var orchestrator = new Orchestrator(processors, serializer, logger);
        await orchestrator.RunAsync();
    }
}
