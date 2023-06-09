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
    private readonly Configuration? configuration;
    private readonly ILogger logger;
    private readonly IList<IProcessor> processors;

    public Generator(IList<ISourceProvider>? sourceProviders = null, ISerializer? serializer = null, Configuration? configuration = null)
    {
        this.logger = configuration?.Logger ?? NullLogger.Instance;
        this.sourceProviders = PopulateMissingSourceProviders(sourceProviders, configuration);
        this.serializer = serializer ?? new Spdx3JsonSerializer(configuration);
        this.configuration = configuration ?? new Configuration();

        this.processors = new List<IProcessor>()
        {
            new FilesProcessor(this.configuration, this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Files), this.logger),
            new PackagesProcessor(this.configuration, this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Packages), this.logger),
        };
    }

    // TODO this should happen in a build or bootstrapper.
    private IList<ISourceProvider> PopulateMissingSourceProviders(IList<ISourceProvider>? sourceProviders, Configuration? configuration)
    {
        var sourceProvidersComplete = sourceProviders
             ?? new List<ISourceProvider>()
             {
                new FileSourceProvider(configuration),
                new PackageSourceProvider(configuration),
                new RunAsUserInfoProvider(configuration),
             };

        if (!sourceProvidersComplete.Any(s => s.SourceType == Enums.SourceType.Files))
        {
            sourceProvidersComplete.Add(new FileSourceProvider(configuration));
        }

        if (!sourceProvidersComplete.Any(s => s.SourceType == Enums.SourceType.Packages))
        {
            sourceProvidersComplete.Add(new PackageSourceProvider(configuration));
        }

        if (!sourceProvidersComplete.Any(s => s.SourceType == Enums.SourceType.UserInfo))
        {
            sourceProvidersComplete.Add(new RunAsUserInfoProvider(configuration));
        }

        return sourceProvidersComplete;
    }

    public async Task GenerateSBOM()
    {
        // Figure out profile.
        // By default we generate software profile

        var softwareProfileOrchestrator = new SoftwareProfileOrchestrator(configuration, processors, sourceProviders, serializer, logger);
        await softwareProfileOrchestrator.RunAsync();
    }
}
