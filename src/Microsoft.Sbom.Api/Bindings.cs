// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities.Output;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Logging;
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
using Microsoft.Sbom.Contracts.Interfaces;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Ninject;
using Ninject.Modules;
using PowerArgs;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

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

            IEnumerable<Type> BindAllTypesThatImplement<T>(params string[] partialAssemblyNames)
            {
                var names = partialAssemblyNames.Append(Assembly.GetExecutingAssembly().GetName().Name);
                var dlls = Directory
                    .GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.dll")
                    .Select(x => Assembly.Load(AssemblyName.GetAssemblyName(x))).ToArray();
                
                var types = names
                .Select(name => dlls.Where(a => a.FullName.Contains(name))
                .Select(assembly => assembly.GetTypes())
                .SelectMany(type => type)
                .Where(type => typeof(T).IsAssignableFrom(type) && !type.IsInterface && !type.IsAbstract))
                .SelectMany(type => type);

                return types.ForEach(type => Bind<T>().To(type)).ToList();
            }

            #region Bind all manifest parsers

            // Search external assemblies
            BindAllTypesThatImplement<IManifestInterface>("Parsers");

            Bind<ManifestData>().ToProvider<ManifestDataProvider>().InSingletonScope();
            Bind<ManifestParserProvider>().ToSelf().InSingletonScope().OnActivation<ManifestParserProvider>(m => m.Init());
            Bind<FileHashesDictionary>().ToProvider<FileHashesDictionaryProvider>().InSingletonScope();

            #endregion

            #region Bind all manifest generators

            BindAllTypesThatImplement<IManifestGenerator>("Parsers");

            Bind<ManifestGeneratorProvider>().ToSelf().InSingletonScope().OnActivation<ManifestGeneratorProvider>(mg => mg.Init());

            #endregion

            #region Bind all signature validators

            BindAllTypesThatImplement<ISignValidator>("Parsers");

            Bind<ISignValidationProvider>().To<SignValidationProvider>().InSingletonScope().OnActivation<SignValidationProvider>(s => s.Init());

            #endregion

            #region Manifest Config

            BindAllTypesThatImplement<IManifestConfigHandler>("Parsers");
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
            Bind<IWorkflow>().To<SBOMParserBasedValidationWorkflow>().Named(nameof(SBOMParserBasedValidationWorkflow));

            #endregion

            BindAllTypesThatImplement<ConfigValidator>();

            #region Bind metadata providers

            BindAllTypesThatImplement<IMetadataProvider>("Microsoft.Sbom.");

            Bind<IMetadataBuilderFactory>().To<MetadataBuilderFactory>();

            #endregion

            #region Bind all sources providers.

            BindAllTypesThatImplement<ISourcesProvider>();

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
            Bind<FileFilterer>().ToSelf().InThreadScope();

            #endregion

            #region Bind all hash algorithm providers

            BindAllTypesThatImplement<IAlgorithmNames>("Parsers", "Contract");

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
