using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Creation;
using Microsoft.Sbom.File;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.JsonSerializer;
using Microsoft.Sbom.Package;
using Microsoft.Sbom.Processors;

namespace Microsoft.Sbom;
public class Generator
{
    private readonly IList<ISourceProvider> sourceProviders;
    private readonly ISerializer serializer;
    private readonly ILogger logger;
    private readonly IList<IProcessor> processors;

    public Generator(IList<ISourceProvider>? sourceProviders = null, ISerializer? serializer = null, Configuration? configuration = null)
    {
        this.logger = configuration?.Logger ?? NullLogger.Instance;
        this.sourceProviders = sourceProviders
            ?? new List<ISourceProvider>()
            {
                new FileSourceProvider(configuration),
                new PackageSourceProvider(configuration),
                new RunAsUserInfoProvider(configuration),
                new CustomUserInfoProvider("Aasim Malladi", "aamallad@microsoft.com"),
            };
        this.serializer = serializer ?? new Spdx3JsonSerializer(configuration);

        this.processors = new List<IProcessor>()
        {
            new FilesProcessor(this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Files), this.logger),
            new PackagesProcessor(this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Packages), this.logger),
        };
    }

    public async Task GenerateSBOM()
    {
        // Figure out profile.
        // By default we generate software profile

        var softwareProfileOrchestrator = new SoftwareProfileOrchestrator(processors, sourceProviders, serializer, logger);
        await softwareProfileOrchestrator.RunAsync();
    }
}
