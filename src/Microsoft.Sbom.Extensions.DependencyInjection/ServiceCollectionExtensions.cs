// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.ComponentDetection.Common;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Detectors.CocoaPods;
using Microsoft.ComponentDetection.Detectors.Conan;
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
using Microsoft.ComponentDetection.Orchestrator.Experiments;
using Microsoft.ComponentDetection.Orchestrator.Services;
using Microsoft.ComponentDetection.Orchestrator.Services.GraphTranslation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
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
using Microsoft.Sbom.Api.PackageDetails;
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
using Serilog.Filters;
using Serilog.Sinks.Map;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
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
            .AddTransient(x =>
            {
                logLevel = x.GetService<InputConfiguration>()?.Verbosity?.Value ?? logLevel;
                return Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.ControlledBy(new LoggingLevelSwitch { MinimumLevel = logLevel })
                    .Filter.ByExcluding(Matching.FromSource("System.Net.Http.HttpClient"))
                    .Enrich.With<LoggingEnricher>()
                    .Enrich.FromLogContext()
                    .WriteTo.Map(
                        LoggingEnricher.LogFilePathPropertyName,
                        (logFilePath, wt) => wt.Async(x => x.File($"{logFilePath}")),
                        1) // sinkMapCountLimit
                    .WriteTo.Map<bool>(
                        LoggingEnricher.PrintStderrPropertyName,
                        (printLogsToStderr, wt) => wt.Logger(lc => lc
                            .WriteTo.Console(outputTemplate: Constants.LoggerTemplate, standardErrorFromLevel: printLogsToStderr ? LogEventLevel.Debug : null)

                            // Don't write the detection times table from DetectorProcessingService to the console, only the log file
                            .Filter.ByExcluding(Matching.WithProperty<string>("DetectionTimeLine", x => !string.IsNullOrEmpty(x)))),
                        1) // sinkMapCountLimit
                    .CreateLogger();
            })
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
            .AddTransient<ILicenseInformationService, LicenseInformationService>()
            .AddSingleton<IPackageDetailsFactory, PackageDetailsFactory>()
            .AddSingleton<IPackageManagerUtils<NugetUtils>, NugetUtils>()
            .AddSingleton<IPackageManagerUtils<MavenUtils>, MavenUtils>()
            .AddSingleton<IPackageManagerUtils<RubyGemsUtils>, RubyGemsUtils>()
            .AddSingleton<IPackageManagerUtils<PypiUtils>, PypiUtils>()
            .AddSingleton<IOSUtils, OSUtils>()
            .AddSingleton<IEnvironmentWrapper, EnvironmentWrapper>()
            .AddSingleton<IFileSystemUtilsExtension, FileSystemUtilsExtension>()
            .AddSingleton<ISbomConfigProvider, SbomConfigProvider>()
            .AddSingleton<IRecorder, TelemetryRecorder>()
            .AddSingleton<IFileTypeUtils, FileTypeUtils>()
            .AddSingleton<ISignValidationProvider, SignValidationProvider>()
            .AddSingleton<IManifestParserProvider, ManifestParserProvider>()
            .AddSingleton(x => {
                var comparer = x.GetRequiredService<IOSUtils>().GetFileSystemStringComparer();
                return new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>(comparer));
            })
            .AddSingleton<IFileTypeUtils, FileTypeUtils>()
            .AddSingleton<IHashAlgorithmProvider, HashAlgorithmProvider>()
            .AddSingleton<IAssemblyConfig, AssemblyConfig>()
            .AddSingleton<ComponentDetectorCachedExecutor>()
            .AddSingleton<ILicenseInformationFetcher, LicenseInformationFetcher>()
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
            .AddScoped<ISBOMValidator, SbomValidator>()
            .AddSingleton(x =>
            {
                var fileSystemUtils = x.GetRequiredService<IFileSystemUtils>();
                var sbomConfigs = x.GetRequiredService<ISbomConfigProvider>();
                var osUtils = x.GetRequiredService<IOSUtils>();
                var configuration = x.GetRequiredService<IConfiguration>();

                var manifestData = new ManifestData();

                if (!configuration.ManifestInfo.Value.Contains(Constants.SPDX22ManifestInfo))
                {
                    var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo?.Value?.FirstOrDefault());
                    var parserProvider = x.GetRequiredService<IManifestParserProvider>();
                    var manifestValue = fileSystemUtils.ReadAllText(sbomConfig.ManifestJsonFilePath);
                    manifestData = parserProvider.Get(sbomConfig.ManifestInfo).ParseManifest(manifestValue);
                    manifestData.HashesMap = new ConcurrentDictionary<string, Checksum[]>(manifestData.HashesMap, osUtils.GetFileSystemStringComparer());
                }

                return manifestData;
            })
            .ConfigureLoggingProviders()
            .ConfigureComponentDetectors()
            .ConfigureComponentDetectionSharedServices()
            .ConfigureComponentDetectionCommandLineServices()
            .AddHttpClient<LicenseInformationService>();

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

        return services;
    }

    public static IServiceCollection ConfigureComponentDetectionCommandLineServices(this IServiceCollection services)
    {
        services.AddSingleton<IScanExecutionService, ScanExecutionService>();
        services.AddSingleton<IDetectorProcessingService, DetectorProcessingService>();
        services.AddSingleton<IDetectorRestrictionService, DetectorRestrictionService>();
        services.AddSingleton<IArgumentHelper, ArgumentHelper>();

        return services;
    }

    public static IServiceCollection ConfigureComponentDetectionSharedServices(this IServiceCollection services)
    {
        services.AddSingleton<IFileWritingService, FileWritingService>();
        services.AddSingleton<IArgumentHelper, ArgumentHelper>();
        services.AddSingleton<ICommandLineInvocationService, CommandLineInvocationService>();
        services.AddSingleton<IComponentStreamEnumerableFactory, ComponentStreamEnumerableFactory>();
        services.AddSingleton<IConsoleWritingService, ConsoleWritingService>();
        services.AddSingleton<IDockerService, DockerService>();
        services.AddSingleton<IEnvironmentVariableService, EnvironmentVariableService>();
        services.AddSingleton<IObservableDirectoryWalkerFactory, FastDirectoryWalkerFactory>();
        services.AddSingleton<IFileUtilityService, FileUtilityService>();
        services.AddSingleton<IFileWritingService, FileWritingService>();
        services.AddSingleton<IGraphTranslationService, DefaultGraphTranslationService>();
        services.AddSingleton<IPathUtilityService, PathUtilityService>();
        services.AddSingleton<ISafeFileEnumerableFactory, SafeFileEnumerableFactory>();
        services.AddSingleton<IExperimentService, ExperimentService>();

        return services;
    }

    public static IServiceCollection ConfigureComponentDetectors(this IServiceCollection services)
    {
        services.AddSingleton<IComponentDetector, PodComponentDetector>();
        services.AddSingleton<IComponentDetector, ConanLockComponentDetector>();
        services.AddSingleton<IComponentDetector, CondaLockComponentDetector>();
        services.AddSingleton<IComponentDetector, DockerfileComponentDetector>();
        services.AddSingleton<IComponentDetector, GoComponentDetector>();
        services.AddSingleton<IComponentDetector, GradleComponentDetector>();
        services.AddSingleton<IComponentDetector, IvyDetector>();
        services.AddSingleton<ILinuxScanner, LinuxScanner>();
        services.AddSingleton<IComponentDetector, LinuxContainerDetector>();
        services.AddSingleton<IMavenCommandService, MavenCommandService>();
        services.AddSingleton<IMavenStyleDependencyGraphParserService, MavenStyleDependencyGraphParserService>();
        services.AddSingleton<IComponentDetector, MvnCliComponentDetector>();
        services.AddSingleton<IComponentDetector, NpmComponentDetector>();
        services.AddSingleton<IComponentDetector, NpmComponentDetectorWithRoots>();
        services.AddSingleton<IComponentDetector, NpmLockfile3Detector>();
        services.AddSingleton<IComponentDetector, NuGetComponentDetector>();
        services.AddSingleton<IComponentDetector, NuGetPackagesConfigDetector>();
        services.AddSingleton<IComponentDetector, NuGetProjectModelProjectCentricComponentDetector>();
        services.AddSingleton<IPyPiClient, PyPiClient>();
        services.AddSingleton<ISimplePyPiClient, SimplePyPiClient>();
        services.AddSingleton<IPythonCommandService, PythonCommandService>();
        services.AddSingleton<IPythonResolver, PythonResolver>();
        services.AddSingleton<ISimplePythonResolver, SimplePythonResolver>();
        services.AddSingleton<IComponentDetector, PipComponentDetector>();
        services.AddSingleton<IComponentDetector, SimplePipComponentDetector>();
        services.AddSingleton<IComponentDetector, PnpmComponentDetector>();
        services.AddSingleton<IComponentDetector, PoetryComponentDetector>();
        services.AddSingleton<IComponentDetector, RubyComponentDetector>();
        services.AddSingleton<IComponentDetector, RustCrateDetector>();
        services.AddSingleton<IComponentDetector, Spdx22ComponentDetector>();
        services.AddSingleton<IComponentDetector, VcpkgComponentDetector>();
        services.AddSingleton<IYarnLockParser, YarnLockParser>();
        services.AddSingleton<IYarnLockFileFactory, YarnLockFileFactory>();
        services.AddSingleton<IComponentDetector, YarnLockComponentDetector>();

        return services;
    }
}
