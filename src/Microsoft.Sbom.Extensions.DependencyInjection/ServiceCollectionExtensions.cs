// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.Build.Utilities;
using Microsoft.ComponentDetection.Orchestrator;
using Microsoft.ComponentDetection.Orchestrator.Extensions;
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
using Microsoft.Sbom.Api.FormatValidator;
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
using Constants = Microsoft.Sbom.Api.Utils.Constants;
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

    public static IServiceCollection AddSbomTool(this IServiceCollection services, LogEventLevel logLevel = LogEventLevel.Information, TaskLoggingHelper? taskLoggingHelper = null)
    {
        services
            .AddSingleton<IConfiguration, Configuration>()
            .AddTransient(_ => FileSystemUtilsProvider.CreateInstance(CreateLogger(logLevel, taskLoggingHelper)))
            .AddTransient(x =>
            {
                logLevel = x.GetService<InputConfiguration>()?.Verbosity?.Value ?? logLevel;
                return Log.Logger = CreateLogger(logLevel, taskLoggingHelper);
            })
            .AddTransient<IWorkflow<SbomParserBasedValidationWorkflow>, SbomParserBasedValidationWorkflow>()
            .AddTransient<IWorkflow<SbomGenerationWorkflow>, SbomGenerationWorkflow>()
            .AddTransient<IWorkflow<SbomRedactionWorkflow>, SbomRedactionWorkflow>()
            .AddTransient<ISbomRedactor, SbomRedactor>()
            .AddTransient<ValidatedSbomFactory>()
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
            .AddTransient<IProcessExecutor, ProcessExecutor>()
            .AddTransient<IComponentDetector, ComponentDetector>()
            .AddTransient<IMetadataBuilderFactory, MetadataBuilderFactory>()
            .AddTransient<FileInfoWriter>()
            .AddTransient<ComponentToExternalReferenceInfoConverter>()
            .AddTransient<ExternalDocumentReferenceWriter>()
            .AddTransient<SbomComponentsWalker>()
            .AddTransient<FileListEnumerator>()
            .AddTransient<ISbomReaderForExternalDocumentReference, SPDXSbomReaderForExternalDocumentReference>()
            .AddTransient<SbomMetadata>()
            .AddTransient<ILicenseInformationService, LicenseInformationService>()
            .AddSingleton<IPackageDetailsFactory, PackageDetailsFactory>()
            .AddSingleton<IPackageManagerUtils<NugetUtils>, NugetUtils>()
            .AddSingleton<IPackageManagerUtils<MavenUtils>, MavenUtils>()
            .AddSingleton<IPackageManagerUtils<RubyGemsUtils>, RubyGemsUtils>()
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
            .AddSingleton<InternalSbomFileInfoDeduplicator>()
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
            .AddScoped<ISbomGenerator, SbomGenerator>()
            .AddScoped<ISbomValidator, SbomValidator>()
            .AddSingleton(x =>
            {
                var fileSystemUtils = x.GetRequiredService<IFileSystemUtils>();
                var sbomConfigs = x.GetRequiredService<ISbomConfigProvider>();
                var osUtils = x.GetRequiredService<IOSUtils>();
                var configuration = x.GetRequiredService<IConfiguration>();

                var manifestData = new ManifestData();

                if (!configuration.ManifestInfo.Value.Any(manifestInfo => Constants.SupportedSpdxManifests.Contains(manifestInfo)))
                {
                    var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo?.Value?.FirstOrDefault());
                    var parserProvider = x.GetRequiredService<IManifestParserProvider>();
                    var manifestValue = fileSystemUtils.ReadAllText(sbomConfig.ManifestJsonFilePath);
                    manifestData = parserProvider.Get(sbomConfig.ManifestInfo).ParseManifest(manifestValue);
                    manifestData.HashesMap = new ConcurrentDictionary<string, Checksum[]>(manifestData.HashesMap, osUtils.GetFileSystemStringComparer());
                }

                return manifestData;
            })
            .AddComponentDetection()
            .ConfigureLoggingProviders()
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

    private static ILogger CreateLogger(LogEventLevel logLevel, TaskLoggingHelper? taskLoggingHelper = null)
    {
        if (taskLoggingHelper == null)
        {
            return new RemapComponentDetectionErrorsToWarningsLogger(
                new LoggerConfiguration()
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
                    .CreateLogger());
        }
        else
        {
            return new MSBuildLogger(taskLoggingHelper);
        }
    }
}
