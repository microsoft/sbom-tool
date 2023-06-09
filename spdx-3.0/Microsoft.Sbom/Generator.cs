using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Creation;
using Microsoft.Sbom.File;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.JsonSerializer;
using Microsoft.Sbom.Package;
using Microsoft.Sbom.Processors;
using Microsoft.Sbom.Utils;

namespace Microsoft.Sbom;
public class Generator
{
    private readonly IList<ISourceProvider> sourceProviders;
    private readonly ISerializer serializer;
    private readonly ILogger logger;
    private readonly IList<IProcessor> processors;
    private readonly IdentifierUtils identifierUtils;
    private readonly string documentName;

    internal Generator(IList<ISourceProvider> sourceProviders, ISerializer serializer, Configuration configuration, ILogger logger)
    {
        this.logger = logger;
        this.sourceProviders = sourceProviders;
        this.serializer = serializer;
        this.identifierUtils = new IdentifierUtils(configuration.Namespace ?? Constants.DefaultNamespace);
        this.documentName = configuration.Name ?? Constants.DefaultDocumentName;

        this.processors = new List<IProcessor>()
        {
            new FilesProcessor(this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Files), this.identifierUtils, this.logger),
            new PackagesProcessor(this.sourceProviders.Where(p => p.SourceType == Enums.SourceType.Packages), this.identifierUtils, this.logger),
        };
    }

    public async Task GenerateSBOM()
    {
        // Figure out profile.
        // By default we generate software profile
        var softwareProfileOrchestrator = new SoftwareProfileOrchestrator(processors, sourceProviders, serializer, identifierUtils, documentName, logger);
        await softwareProfileOrchestrator.RunAsync();
    }

    public class Builder
    {
        private IList<ISourceProvider>? sourceProviders;
        private ISerializer? serializer;
        private Configuration? configuration;
        private ILogger? logger;

        public Builder WithSourceProviders(IList<ISourceProvider> sourceProviders)
        {
            this.sourceProviders = sourceProviders;
            return this;
        }

        public Builder SerializeTo(ISerializer serializer)
        {
            this.serializer = serializer;
            return this;
        }

        public Builder WithConfiguration(Configuration configuration)
        {
            this.configuration = configuration;
            return this;
        }

        public Builder AddLogging(ILogger logger)
        {
            this.logger = logger;
            return this;
        }

        public Generator Build()
        {
            this.logger ??= NullLogger.Instance;
            this.configuration ??= new Configuration();
            this.serializer ??= new Spdx3JsonSerializer(configuration, this.logger);
            this.sourceProviders = PopulateMissingSourceProviders(sourceProviders, this.configuration, this.logger);
            
            return new Generator(sourceProviders, serializer, configuration, logger);
        }

        private IList<ISourceProvider> PopulateMissingSourceProviders(IList<ISourceProvider>? sourceProviders, Configuration configuration, ILogger logger)
        {
            var sourceProvidersComplete = sourceProviders
                 ?? new List<ISourceProvider>()
                 {
                    new FileSourceProvider(configuration, logger),
                    new PackageSourceProvider(configuration, logger),
                    new RunAsUserInfoProvider(configuration, logger),
                 };

            if (!sourceProvidersComplete.Any(s => s.SourceType == Enums.SourceType.Files))
            {
                sourceProvidersComplete.Add(new FileSourceProvider(configuration, logger));
            }

            if (!sourceProvidersComplete.Any(s => s.SourceType == Enums.SourceType.Packages))
            {
                sourceProvidersComplete.Add(new PackageSourceProvider(configuration, logger));
            }

            if (!sourceProvidersComplete.Any(s => s.SourceType == Enums.SourceType.UserInfo))
            {
                sourceProvidersComplete.Add(new RunAsUserInfoProvider(configuration, logger));
            }

            return sourceProvidersComplete;
        }
    }
}
