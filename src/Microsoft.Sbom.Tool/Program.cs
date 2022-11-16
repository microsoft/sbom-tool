// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Config.Args;
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
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Common.Extensions;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Interfaces;
using Microsoft.Sbom.Extensions;
using PowerArgs;
using Serilog;
using Serilog.Core;
using IConfiguration = Microsoft.Sbom.Common.Config.IConfiguration;

namespace Microsoft.Sbom.Tool
{
    internal class Program
    {
        internal static string Name => NameValue.Value;

        internal static string Version => VersionValue.Value;

        private const string ConfigurationKey = "configuration";

        private static readonly Lazy<string> NameValue = new Lazy<string>(() =>
        {
            return typeof(Program).GetTypeInfo().Assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product ?? "sbomtool";
        });

        private static readonly Lazy<string> VersionValue = new Lazy<string>(() =>
        {
            return typeof(Program).GetTypeInfo().Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty;
        });

        public static async Task Main(string[] args)
        {
            var result = await Args.InvokeActionAsync<SbomToolCmdRunner>(args);

            using var host = Host.CreateDefaultBuilder(args)
            .ConfigureServices((host, services) =>
            {
                services = result.ActionArgs switch
                {
                    ValidationArgs v => services.AddHostedService<ValidationService>(),
                    GenerationArgs g => services.AddHostedService<GenerationService>(),
                    _ => services
                };

                services
                    .AddScoped(_ => FileSystemUtilsProvider.CreateInstance())
                    .AddScoped<ConfigFileParser>()
                    .AddSingleton(typeof(IConfigurationBuilder<>), typeof(ConfigurationBuilder<>))
                    .AddSingleton(x =>
                    {
                        var validationConfigurationBuilder = x.GetService<IConfigurationBuilder<ValidationArgs>>();
                        var generationConfigurationBuilder = x.GetService<IConfigurationBuilder<GenerationArgs>>();
                        var configuration = result.ActionArgs switch
                        {
                            ValidationArgs v => validationConfigurationBuilder.GetConfiguration(v).GetAwaiter().GetResult(),
                            GenerationArgs g => generationConfigurationBuilder.GetConfiguration(g).GetAwaiter().GetResult(),
                            _ => default
                        };
                        host.Properties[ConfigurationKey] = configuration;
                        return configuration;
                    })
                    .AddScoped<ILogger>(x =>
                    {
                        var configuration = host.Properties[ConfigurationKey] as Common.Config.IConfiguration;
                        return new LoggerConfiguration().MinimumLevel.ControlledBy(new LoggingLevelSwitch { MinimumLevel = configuration.Verbosity.Value })
                            .WriteTo.Console(outputTemplate: Api.Utils.Constants.LoggerTemplate)
                            .CreateLogger();
                    })
                    .AddScoped<IWorkflow<SBOMValidationWorkflow>, SBOMValidationWorkflow>()
                    .AddScoped<IWorkflow<SBOMParserBasedValidationWorkflow>, SBOMParserBasedValidationWorkflow>()
                    .AddScoped<IWorkflow<SBOMGenerationWorkflow>, SBOMGenerationWorkflow>()
                    .AddScoped<DirectoryWalker>()
                    .AddScoped<IFilter<DownloadedRootPathFilter>, DownloadedRootPathFilter>()
                    .AddScoped<IFilter<ManifestFolderFilter>, ManifestFolderFilter>()
                    .AddScoped<ManifestFolderFilterer>()
                    .AddScoped<ChannelUtils>()
                    .AddScoped<FileHasher>()
                    .AddScoped<IHashCodeGenerator, HashCodeGenerator>()
                    .AddScoped<IManifestPathConverter, SbomToolManifestPathConverter>()
                    .AddScoped<ManifestGeneratorProvider>()
                    .AddScoped<HashValidator>()
                    .AddScoped<ValidationResultGenerator>()
                    .AddScoped<IOutputWriter, FileOutputWriter>()
                    .AddScoped<ManifestFileFilterer>()
                    .AddScoped<FilesValidator>()
                    .AddScoped<ConcurrentSha256HashValidator>()
                    .AddScoped<EnumeratorChannel>()
                    .AddScoped<FilesValidator>()
                    .AddScoped<SBOMFileToFileInfoConverter>()
                    .AddScoped<FileFilterer>()
                    .AddScoped<PackagesWalker>()
                    .AddScoped<PackageInfoJsonWriter>()
                    .AddScoped<ComponentToPackageInfoConverter>()
                    .AddScoped<IJsonArrayGenerator<FileArrayGenerator>, FileArrayGenerator>()
                    .AddScoped<IJsonArrayGenerator<PackageArrayGenerator>, PackageArrayGenerator>()
                    .AddScoped<IJsonArrayGenerator<RelationshipsArrayGenerator>, RelationshipsArrayGenerator>()
                    .AddScoped<IJsonArrayGenerator<ExternalDocumentReferenceGenerator>, ExternalDocumentReferenceGenerator>()
                    .AddScoped<RelationshipGenerator>()
                    .AddScoped<ConfigSanitizer>()
                    .AddScoped<ComponentDetector>()
                    .AddScoped<IMetadataBuilderFactory, MetadataBuilderFactory>()
                    .AddScoped<FileInfoWriter>()
                    .AddScoped<ComponentToExternalReferenceInfoConverter>()
                    .AddScoped<ExternalDocumentReferenceWriter>()
                    .AddScoped<SBOMComponentsWalker>()
                    .AddScoped<FileListEnumerator>()
                    .AddScoped<ISBOMReaderForExternalDocumentReference, SPDXSBOMReaderForExternalDocumentReference>()
                    .AddScoped<SBOMMetadata>()
                    .AddSingleton<IOSUtils, OSUtils>()
                    .AddSingleton<IEnvironmentWrapper, EnvironmentWrapper>()
                    .AddSingleton<IFileSystemUtilsExtension, FileSystemUtilsExtension>()
                    .AddSingleton<ISbomConfigProvider, SbomConfigProvider>()
                    .AddSingleton<IRecorder, TelemetryRecorder>()
                    .AddSingleton<IFileTypeUtils, FileTypeUtils>()
                    .AddSingleton<ISignValidationProvider, SignValidationProvider>()
                    .AddSingleton<IManifestParserProvider, ManifestParserProvider>()
                    .AddSingleton<FileHashesDictionary>(x => new (new ConcurrentDictionary<string, FileHashes>()))
                    .AddSingleton<IFileTypeUtils, FileTypeUtils>()
                    .AddSingleton<IHashAlgorithmProvider, HashAlgorithmProvider>()
                    .AddSingleton<IAssemblyConfig, AssemblyConfig>()
                    .AddSingleton<ComponentDetectorCachedExecutor>()
                    .AddSingleton<InternalSBOMFileInfoDeduplicator>()
                    .AddSingleton<ExternalReferenceInfoToPathConverter>()
                    .AddSingleton<ExternalReferenceDeduplicator>()
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
                    .AddScoped(x =>
                    {
                        IFileSystemUtils fileSystemUtils = x.GetService<IFileSystemUtils>();
                        ISbomConfigProvider sbomConfigs = x.GetService<ISbomConfigProvider>();
                        IOSUtils osUtils = x.GetService<IOSUtils>();
                        IConfiguration configuration = x.GetService<IConfiguration>();

                        var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo?.Value?.FirstOrDefault());
                        var parserProvider = x.GetService<IManifestParserProvider>();
                        var manifestValue = fileSystemUtils.ReadAllText(sbomConfig.ManifestJsonFilePath);
                        var manifestData = parserProvider.Get(sbomConfig.ManifestInfo).ParseManifest(manifestValue);
                        manifestData.HashesMap = new ConcurrentDictionary<string, Checksum[]>(manifestData.HashesMap, osUtils.GetFileSystemStringComparer());

                        return manifestData;
                    });
                })
            .UseConsoleLifetime()
            .Build();

            await host.RunAsync();
        }
    }
}
