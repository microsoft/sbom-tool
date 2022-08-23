// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Logging;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts.Interfaces;
using Ninject;
using Ninject.Extensions.Conventions;
using Ninject.Modules;
using Serilog;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Common.Extensions;

namespace Microsoft.Sbom.Api
{
    /// <summary>
    /// Creates the Ninject bindings for the whole project.
    /// </summary>
    /// <remarks>
    /// Microsoft.Sbom.Api.dll is the assembly name of the SBOM API project.
    /// Using pattern matching until all bindings are in the same assembly. 
    /// </remarks>
    public class Bindings : NinjectModule
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("StyleCop.CSharp.ReadabilityRules", "SA1123:Do not place regions within elements", Justification = "Enable documentation of code")]
        public override void Load()
        {
            Bind<IFileSystemUtils>().ToProvider<FileSystemUtilsProvider>().InSingletonScope();

            Bind<ValidationResultGenerator>().ToSelf();
            Bind<IOutputWriter>().To<FileOutputWriter>();
            Bind<IOSUtils>().To<OSUtils>().InSingletonScope();
            Bind<IEnvironmentWrapper>().To<EnvironmentWrapper>().InSingletonScope();
            Bind<ConfigFileParser>().ToSelf();
            Bind<IJsonArrayGenerator>().To<FileArrayGenerator>().Named(nameof(FileArrayGenerator));
            Bind<IJsonArrayGenerator>().To<PackageArrayGenerator>().Named(nameof(PackageArrayGenerator));
            Bind<IJsonArrayGenerator>().To<RelationshipsArrayGenerator>().Named(nameof(RelationshipsArrayGenerator));
            Bind<IJsonArrayGenerator>().To<ExternalDocumentReferenceGenerator>().Named(nameof(ExternalDocumentReferenceGenerator));
            Bind<ComponentDetector>().ToSelf();
            Bind<IAssemblyConfig>().To<AssemblyConfig>().InSingletonScope();

            Bind<IFilter>().To<DownloadedRootPathFilter>().Named(nameof(DownloadedRootPathFilter)).OnActivation(f => f.Init());
            Bind<IFilter>().To<ManifestFolderFilter>().Named(nameof(ManifestFolderFilter)).OnActivation(f => f.Init());
            Bind<ILogger>().ToProvider<LoggerProvider>();

            #region Bind all manifest parsers

            // Search external assemblies
            Kernel.Bind(scan => scan
                                .FromAssembliesMatching("*Parsers*")
                                .SelectAllClasses()
                                .InheritedFrom<IManifestInterface>()
                                .BindAllInterfaces());

            // Search this assembly in case --self-contained is used with dotnet publish
            Kernel.Bind(scan => scan
                                .FromThisAssembly()
                                .SelectAllClasses()
                                .InheritedFrom<IManifestInterface>()
                                .BindAllInterfaces());

            Bind<ManifestData>().ToProvider<ManifestDataProvider>().InSingletonScope();
            Bind<ManifestParserProvider>().ToSelf().InSingletonScope().OnActivation<ManifestParserProvider>(m => m.Init());

            #endregion

            #region Bind all manifest generators

            // Search external assemblies
            Kernel.Bind(scan => scan
                                .FromAssembliesMatching("*Parsers*")
                                .SelectAllClasses()
                                .InheritedFrom<IManifestGenerator>()
                                .BindAllInterfaces());

            // Search this assembly in case --self-contained is used with dotnet publish
            Kernel.Bind(scan => scan
                                .FromThisAssembly()
                                .SelectAllClasses()
                                .InheritedFrom<IManifestGenerator>()
                                .BindAllInterfaces());

            Bind<ManifestGeneratorProvider>().ToSelf().InSingletonScope().OnActivation<ManifestGeneratorProvider>(mg => mg.Init());

            #endregion

            #region Bind all signature validators
            Kernel.Bind(scan => scan
                                .FromAssembliesMatching("*Parsers*")
                                .SelectAllClasses()
                                .InheritedFrom<ISignValidator>()
                                .BindAllInterfaces());

            Kernel.Bind(scan => scan
                                .FromThisAssembly()
                                .SelectAllClasses()
                                .InheritedFrom<ISignValidator>()
                                .BindAllInterfaces());

            Bind<SignValidationProvider>().ToSelf().InSingletonScope().OnActivation<SignValidationProvider>(s => s.Init());

            #endregion

            #region Manifest Config

            Kernel.Bind(scan => scan
               .FromAssembliesMatching("*Parsers*")
               .SelectAllClasses()
               .InheritedFrom<IManifestConfigHandler>()
               .BindAllInterfaces());

            Kernel.Bind(scan => scan
               .FromThisAssembly()
               .SelectAllClasses()
               .InheritedFrom<IManifestConfigHandler>()
               .BindAllInterfaces());

            Bind<ISbomConfigProvider>().To<SbomConfigProvider>().InSingletonScope();
            Bind<ISbomConfigFactory>().To<SbomConfigFactory>();

            #endregion

            #region QuickBuild Manifest workflow bindings
            Bind<IHashCodeGenerator>().To<HashCodeGenerator>();
            Bind<IManifestPathConverter>().To<SbomToolManifestPathConverter>();
            #endregion

            #region AutoMapper bindings
            var mapperConfiguration = new MapperConfiguration(cfg => cfg.AddProfile<ConfigurationProfile>());
            mapperConfiguration.AssertConfigurationIsValid();
            Bind<MapperConfiguration>().ToConstant(mapperConfiguration).InSingletonScope();
            Bind<IMapper>().ToMethod(ctx =>
                new Mapper(mapperConfiguration, type => ctx.Kernel.Get(type)));

            #endregion

            #region Workflows

            Bind<IWorkflow>().To<SBOMValidationWorkflow>().Named(nameof(SBOMValidationWorkflow));
            Bind<IWorkflow>().To<SBOMGenerationWorkflow>().Named(nameof(SBOMGenerationWorkflow));

            #endregion

            Kernel.Bind(scan => scan
                                .FromThisAssembly()
                                .SelectAllClasses()
                                .InheritedFrom<ConfigValidator>()
                                .BindAllBaseClasses());

            #region Bind metadata providers

            Kernel.Bind(scan => scan
                                .FromAssembliesMatching("Microsoft.Sbom.*")
                                .SelectAllClasses()
                                .InheritedFrom<IMetadataProvider>()
                                .BindAllInterfaces());

            Bind<IMetadataBuilderFactory>().To<MetadataBuilderFactory>();

            #endregion

            #region Bind all sources providers.
            Kernel.Bind(scan => scan
                                .FromThisAssembly()
                                .SelectAllClasses()
                                .InheritedFrom<ISourcesProvider>()
                                .BindAllInterfaces());
            #endregion

            #region Converters

            Bind<ComponentToExternalReferenceInfoConverter>().ToSelf().InThreadScope();
            Bind<ExternalReferenceInfoToPathConverter>().ToSelf().InThreadScope();

            #endregion

            #region Executors

            Bind<ChannelUtils>().ToSelf().InThreadScope();
            Bind<FileHasher>().ToSelf().InThreadScope();
            Bind<HashValidator>().ToSelf().InThreadScope();
            Bind<DirectoryWalker>().ToSelf().InThreadScope();
            Bind<FileListEnumerator>().ToSelf().InThreadScope();
            Bind<ManifestFileFilterer>().ToSelf().InThreadScope();
            Bind<ManifestFolderFilterer>().ToSelf().InThreadScope();
            Bind<PackagesWalker>().ToSelf().InThreadScope();
            Bind<SBOMComponentsWalker>().ToSelf().InThreadScope();
            Bind<ComponentToPackageInfoConverter>().ToSelf().InThreadScope();
            Bind<RelationshipGenerator>().ToSelf().InThreadScope();
            Bind<SBOMFileToFileInfoConverter>().ToSelf().InThreadScope();
            Bind<SBOMPackageToPackageInfoConverter>().ToSelf().InThreadScope();
            Bind<ExternalDocumentReferenceWriter>().ToSelf().InThreadScope();
            Bind<ISBOMReaderForExternalDocumentReference>().To<SPDXSBOMReaderForExternalDocumentReference>().InThreadScope();

            #endregion

            #region Bind all hash algorithm providers

            // TODO: Put all dependent assemblies in the plugins folder and search using
            // that path here.
            Kernel.Bind(scan => scan
                                    .FromAssembliesMatching("*Parsers*", "*Contract*")
                                    .SelectAllClasses()
                                    .InheritedFrom<IAlgorithmNames>()
                                    .BindAllInterfaces());

            // We should move all algorithm implementations into their own lib, so that
            // we can remove this additional scan.
            Kernel.Bind(scan => scan.
                                  FromThisAssembly()
                                  .SelectAllClasses()
                                  .InheritedFrom<IAlgorithmNames>()
                                  .BindAllInterfaces());

            Bind<IHashAlgorithmProvider>().To<HashAlgorithmProvider>().InSingletonScope();

            #endregion

            Bind<IRecorder>().To<TelemetryRecorder>().InSingletonScope();
            Bind<ComponentDetectorCachedExecutor>().ToSelf().InSingletonScope();
            Bind<ExternalReferenceDeduplicator>().ToSelf().InSingletonScope();
            Bind<InternalSBOMFileInfoDeduplicator>().ToSelf().InSingletonScope();
            Bind<IFileTypeUtils>().To<FileTypeUtils>().InSingletonScope();
            Bind<IFileSystemUtilsExtension>().To<FileSystemUtilsExtension>().InSingletonScope();
        }
    }
}
