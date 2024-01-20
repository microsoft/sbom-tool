// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.ComponentDetection.Orchestrator.Extensions;
using Microsoft.Extensions.DependencyInjection;
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
using Serilog.Events;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

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
            .AddTransient(_ => FileSystemUtilsProvider.CreateInstance())
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
            .AddTransient<IProcessExecutor, ProcessExecutor>()
            .AddTransient<IComponentDetector, ComponentDetector>()
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
            .AddComponentDetection()
            .AddHttpClient<LicenseInformationService>();

        return services;
    }
}
