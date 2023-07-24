// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.ComponentDetection.Common;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Detectors.CocoaPods;
using Microsoft.ComponentDetection.Detectors.Dockerfile;
using Microsoft.ComponentDetection.Detectors.Go;
using Microsoft.ComponentDetection.Detectors.Gradle;
using Microsoft.ComponentDetection.Detectors.Ivy;
using Microsoft.ComponentDetection.Detectors.Linux;
using Microsoft.ComponentDetection.Detectors.Maven;
using Microsoft.ComponentDetection.Detectors.Npm;
using Microsoft.ComponentDetection.Detectors.NuGet;
using Microsoft.ComponentDetection.Detectors.Pip;
using Microsoft.ComponentDetection.Detectors.Pnpm;
using Microsoft.ComponentDetection.Detectors.Poetry;
using Microsoft.ComponentDetection.Detectors.Ruby;
using Microsoft.ComponentDetection.Detectors.Rust;
using Microsoft.ComponentDetection.Detectors.Spdx;
using Microsoft.ComponentDetection.Detectors.Vcpkg;
using Microsoft.ComponentDetection.Detectors.Yarn;
using Microsoft.ComponentDetection.Detectors.Yarn.Parsers;
using Microsoft.ComponentDetection.Orchestrator;
using Microsoft.ComponentDetection.Orchestrator.ArgumentSets;
using Microsoft.ComponentDetection.Orchestrator.Experiments;
using Microsoft.ComponentDetection.Orchestrator.Experiments.Configs;
using Microsoft.ComponentDetection.Orchestrator.Services;
using Microsoft.ComponentDetection.Orchestrator.Services.GraphTranslation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Config.Extensions;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Common.Extensions;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Interfaces;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Extensions.Logging;
using IComponentDetector = Microsoft.ComponentDetection.Contracts.IComponentDetector;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSbomConfiguration(this IServiceCollection services, InputConfiguration inputConfiguration, LogEventLevel logLevel = LogEventLevel.Information)
    {
        ArgumentNullException.ThrowIfNull(inputConfiguration);
        services
            .AddSingleton(_ =>
            {
                inputConfiguration.ToConfiguration();
                return inputConfiguration;
            })
            .AddSbomTool(logLevel);
        return services;
    }

    public static IServiceCollection AddSbomTool(this IServiceCollection services, LogEventLevel logLevel = LogEventLevel.Information)
    {
        services
            .AddSingleton<IConfiguration, Configuration>()
            .AddTransient(_ => FileSystemUtilsProvider.CreateInstance())
            .AddTransient<ILogger>(x =>
            {
                logLevel = x.GetService<InputConfiguration>()?.Verbosity?.Value ?? logLevel;
                return Log.Logger = new LoggerConfiguration()
                            .MinimumLevel.ControlledBy(new LoggingLevelSwitch { MinimumLevel = logLevel })
                            .WriteTo.Console(outputTemplate: Api.Utils.Constants.LoggerTemplate)
                            .CreateBootstrapLogger();
            })
            .AddTransient<IWorkflow<SbomValidationWorkflow>, SbomValidationWorkflow>()
            .AddTransient<IWorkflow<SbomParserBasedValidationWorkflow>, SbomParserBasedValidationWorkflow>()
            .AddTransient<IWorkflow<SbomGenerationWorkflow>, SbomGenerationWorkflow>()
            .AddTransient<DirectoryWalker>()
            .AddTransient<IFilter<DownloadedRootPathFilter>, DownloadedRootPathFilter>()
            .AddTransient<IFilter<ManifestFolderFilter>, ManifestFolderFilter>()
            .AddTransient<ManifestFolderFilterer>()
            .AddTransient<ChannelUtils>()
            .AddTransient<FileHasher>()
            .AddTransient<IHashCodeGenerator, HashCodeGenerator>()
            .AddTransient<IManifestPathConverter, SbomToolManifestPathConverter>()
            .AddTransient<ManifestGeneratorProvider>()
            .AddTransient<HashValidator>()
            .AddTransient<ValidationResultGenerator>()
            .AddTransient<IOutputWriter, FileOutputWriter>()
            .AddTransient<ManifestFileFilterer>()
            .AddTransient<FilesValidator>()
            .AddTransient<ConcurrentSha256HashValidator>()
            .AddTransient<EnumeratorChannel>()
            .AddTransient<FilesValidator>()
            .AddTransient<SbomFileToFileInfoConverter>()
            .AddTransient<FileFilterer>()
            .AddTransient<PackagesWalker>()
            .AddTransient<PackageInfoJsonWriter>()
            .AddTransient<ComponentToPackageInfoConverter>()
            .AddTransient<IJsonArrayGenerator<FileArrayGenerator>, FileArrayGenerator>()
            .AddTransient<IJsonArrayGenerator<PackageArrayGenerator>, PackageArrayGenerator>()
            .AddTransient<IJsonArrayGenerator<RelationshipsArrayGenerator>, RelationshipsArrayGenerator>()
            .AddTransient<IJsonArrayGenerator<ExternalDocumentReferenceGenerator>, ExternalDocumentReferenceGenerator>()
            .AddTransient<RelationshipGenerator>()
            .AddTransient<ConfigSanitizer>()
            .AddTransient<Api.Utils.IComponentDetector, ComponentDetector>()
            .AddTransient<IMetadataBuilderFactory, MetadataBuilderFactory>()
            .AddTransient<FileInfoWriter>()
            .AddTransient<ComponentToExternalReferenceInfoConverter>()
            .AddTransient<ExternalDocumentReferenceWriter>()
            .AddTransient<SBOMComponentsWalker>()
            .AddTransient<FileListEnumerator>()
            .AddTransient<ISBOMReaderForExternalDocumentReference, SPDXSBOMReaderForExternalDocumentReference>()
            .AddTransient<SBOMMetadata>()
            .AddSingleton<IOSUtils, OSUtils>()
            .AddSingleton<IEnvironmentWrapper, EnvironmentWrapper>()
            .AddSingleton<IFileSystemUtilsExtension, FileSystemUtilsExtension>()
            .AddSingleton<ISbomConfigProvider, SbomConfigProvider>()
            .AddSingleton<IRecorder, TelemetryRecorder>()
            .AddSingleton<IFileTypeUtils, FileTypeUtils>()
            .AddSingleton<ISignValidationProvider, SignValidationProvider>()
            .AddSingleton<IManifestParserProvider, ManifestParserProvider>()
            .AddSingleton<Orchestrator>()
            .AddSingleton<IFileWritingService, FileWritingService>()
            .AddSingleton<IArgumentHelper, ArgumentHelper>()
            // Shared services
            .AddSingleton<ICommandLineInvocationService, CommandLineInvocationService>()
            .AddSingleton<IComponentStreamEnumerableFactory, ComponentStreamEnumerableFactory>()
            .AddSingleton<IConsoleWritingService, ConsoleWritingService>()
            .AddSingleton<IDockerService, DockerService>()
            .AddSingleton<IEnvironmentVariableService, EnvironmentVariableService>()
            .AddSingleton<IObservableDirectoryWalkerFactory, FastDirectoryWalkerFactory>()
            .AddSingleton<IFileUtilityService, FileUtilityService>()
            .AddSingleton<IFileWritingService, FileWritingService>()
            .AddSingleton<IGraphTranslationService, DefaultGraphTranslationService>()
            .AddSingleton<IPathUtilityService, PathUtilityService>()
            .AddSingleton<ISafeFileEnumerableFactory, SafeFileEnumerableFactory>()

            // Command line services
            .AddSingleton<IScanArguments, BcdeArguments>()
            .AddSingleton<IScanArguments, BcdeDevArguments>()
            .AddSingleton<IScanArguments, ListDetectionArgs>()
            .AddSingleton<IArgumentHandlingService, BcdeDevCommandService>()
            .AddSingleton<IArgumentHandlingService, BcdeScanCommandService>()
            .AddSingleton<IArgumentHandlingService, DetectorListingCommandService>()
            .AddSingleton<IBcdeScanExecutionService, BcdeScanExecutionService>()
            .AddSingleton<IDetectorProcessingService, DetectorProcessingService>()
            .AddSingleton<IDetectorRestrictionService, DetectorRestrictionService>()
            .AddSingleton<IArgumentHelper, ArgumentHelper>()

            // Experiments
            .AddSingleton<IExperimentService, ExperimentService>()
            .AddSingleton<IExperimentProcessor, DefaultExperimentProcessor>()
            .AddSingleton<IExperimentConfiguration, NewNugetExperiment>()
            .AddSingleton<IExperimentConfiguration, NpmLockfile3Experiment>()

            // Detectors

            // CocoaPods
            .AddSingleton<IComponentDetector, PodComponentDetector>()

            // Conda
            .AddSingleton<IComponentDetector, CondaLockComponentDetector>()

            // Dockerfile
            .AddSingleton<IComponentDetector, DockerfileComponentDetector>()

            // Go
            .AddSingleton<IComponentDetector, GoComponentDetector>()

            // Gradle
            .AddSingleton<IComponentDetector, GradleComponentDetector>()

            // Ivy
            .AddSingleton<IComponentDetector, IvyDetector>()

            // Linux
            .AddSingleton<ILinuxScanner, LinuxScanner>()
            .AddSingleton<IComponentDetector, LinuxContainerDetector>()

            // Maven
            .AddSingleton<IMavenCommandService, MavenCommandService>()
            .AddSingleton<IMavenStyleDependencyGraphParserService, MavenStyleDependencyGraphParserService>()
            .AddSingleton<IComponentDetector, MvnCliComponentDetector>()

            // npm
            .AddSingleton<IComponentDetector, NpmComponentDetector>()
            .AddSingleton<IComponentDetector, NpmComponentDetectorWithRoots>()
            .AddSingleton<IComponentDetector, NpmLockfile3Detector>()

            // NuGet
            .AddSingleton<IComponentDetector, NuGetComponentDetector>()
            .AddSingleton<IComponentDetector, NuGetPackagesConfigDetector>()
            .AddSingleton<IComponentDetector, NuGetProjectModelProjectCentricComponentDetector>()

            // PIP
            .AddSingleton<IPyPiClient, PyPiClient>()
            .AddSingleton<IPythonCommandService, PythonCommandService>()
            .AddSingleton<IPythonResolver, PythonResolver>()
            .AddSingleton<IComponentDetector, PipComponentDetector>()

            // pnpm
            .AddSingleton<IComponentDetector, PnpmComponentDetector>()

            // Poetry
            .AddSingleton<IComponentDetector, PoetryComponentDetector>()

            // Ruby
            .AddSingleton<IComponentDetector, RubyComponentDetector>()

            // Rust
            .AddSingleton<IComponentDetector, RustCrateDetector>()

            // SPDX
            .AddSingleton<IComponentDetector, Spdx22ComponentDetector>()

            // VCPKG
            .AddSingleton<IComponentDetector, VcpkgComponentDetector>()

            // Yarn
            .AddSingleton<IYarnLockParser, YarnLockParser>()
            .AddSingleton<IYarnLockFileFactory, YarnLockFileFactory>()
            .AddSingleton<IComponentDetector, YarnLockComponentDetector>()
            .AddSingleton(x => {
                var comparer = x.GetRequiredService<IOSUtils>().GetFileSystemStringComparer();
                return new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>(comparer));
            })
            .AddSingleton<IFileTypeUtils, FileTypeUtils>()
            .AddSingleton<IHashAlgorithmProvider, HashAlgorithmProvider>()
            .AddSingleton<IAssemblyConfig, AssemblyConfig>()
            .AddSingleton<ComponentDetectorCachedExecutor>()
            .AddSingleton<InternalSBOMFileInfoDeduplicator>()
            .AddSingleton<ExternalReferenceInfoToPathConverter>()
            .AddSingleton<ExternalReferenceDeduplicator>()
            .AddSingleton<ISbomConfigFactory, SbomConfigFactory>()
            .AddAutoMapper(x => x.AddProfile(new ConfigurationProfile()), typeof(ConfigValidator), typeof(ConfigSanitizer))
            .Scan(scan => scan.FromApplicationDependencies()
                .AddClasses(classes => classes.AssignableTo<ConfigValidator>())
                .As<ConfigValidator>()
                .AddClasses(classes => classes.AssignableToAny(
                    typeof(IAlgorithmNames),
                    typeof(IManifestConfigHandler),
                    typeof(ISignValidator),
                    typeof(ISourcesProvider),
                    typeof(IManifestGenerator),
                    typeof(IMetadataProvider),
                    typeof(IManifestInterface)))
                .AsImplementedInterfaces())
            .AddScoped<ISBOMGenerator, SbomGenerator>()
            .AddSingleton(x =>
            {
                IFileSystemUtils fileSystemUtils = x.GetRequiredService<IFileSystemUtils>();
                ISbomConfigProvider sbomConfigs = x.GetRequiredService<ISbomConfigProvider>();
                IOSUtils osUtils = x.GetRequiredService<IOSUtils>();
                IConfiguration configuration = x.GetRequiredService<IConfiguration>();

                ManifestData manifestData = new ManifestData();

                if (!configuration.ManifestInfo.Value.Contains(Api.Utils.Constants.SPDX22ManifestInfo))
                {
                    var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo?.Value?.FirstOrDefault());
                    var parserProvider = x.GetRequiredService<IManifestParserProvider>();
                    var manifestValue = fileSystemUtils.ReadAllText(sbomConfig.ManifestJsonFilePath);
                    manifestData = parserProvider.Get(sbomConfig.ManifestInfo).ParseManifest(manifestValue);
                    manifestData.HashesMap = new ConcurrentDictionary<string, Checksum[]>(manifestData.HashesMap, osUtils.GetFileSystemStringComparer());
                }

                return manifestData;
            });

        return services;
    }

    public static IServiceCollection ConfigureLoggingProviders(this IServiceCollection services)
    {
        var providers = new LoggerProviderCollection();
        services.AddSingleton(providers);
        services.AddSingleton<ILoggerFactory>(sc =>
        {
            var providerCollection = sc.GetService<LoggerProviderCollection>();
            var factory = new SerilogLoggerFactory(null, true, providerCollection);

            foreach (var provider in sc.GetServices<ILoggerProvider>())
            {
                factory.AddProvider(provider);
            }

            return factory;
        });
        services.AddLogging(l => l.AddFilter<SerilogLoggerProvider>(null, LogLevel.Trace));

        return services;
    }
}