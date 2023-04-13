// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using AutoMapper;
using Microsoft.Sbom.Extensions.Entities;
using Serilog.Events;
using System;
using System.Collections.Generic;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Config.ValueConverters;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Api.Config;

namespace Microsoft.Sbom.Api
{
    /// <summary>
    /// Provides a named profile for the automapper that
    /// generates a mapping for all the classes that map to a configuration object.
    /// </summary>
    public class ConfigurationProfile : Profile
    {
        public ConfigurationProfile()
        {
            // Create config for the validation args, ignoring other action members
            CreateMap<ValidationArgs, InputConfiguration>()
#pragma warning disable CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(c => c.ManifestPath, o => o.Ignore())
#pragma warning restore CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(c => c.PackageName, o => o.Ignore())
                .ForMember(c => c.PackageVersion, o => o.Ignore())
                .ForMember(c => c.BuildListFile, o => o.Ignore())
                .ForMember(c => c.ExternalDocumentReferenceListFile, o => o.Ignore())
                .ForMember(c => c.BuildComponentPath, o => o.Ignore())
                .ForMember(c => c.PackagesList, o => o.Ignore())
                .ForMember(c => c.FilesList, o => o.Ignore())
                .ForMember(c => c.DockerImagesToScan, o => o.Ignore())
                .ForMember(c => c.AdditionalComponentDetectorArgs, o => o.Ignore())
                .ForMember(c => c.GenerationTimestamp, o => o.Ignore())
                .ForMember(c => c.NamespaceUriUniquePart, o => o.Ignore())
                .ForMember(c => c.NamespaceUriBase, o => o.Ignore())
                .ForMember(c => c.DeleteManifestDirIfPresent, o => o.Ignore())
                .ForMember(c => c.PackageSupplier, o => o.Ignore());

            // Create config for the generation args, ignoring other action members
            CreateMap<GenerationArgs, InputConfiguration>()
#pragma warning disable CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(c => c.ManifestPath, o => o.Ignore())
#pragma warning restore CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(c => c.OutputPath, o => o.Ignore())
                .ForMember(c => c.HashAlgorithm, o => o.Ignore())
                .ForMember(c => c.RootPathFilter, o => o.Ignore())
                .ForMember(c => c.CatalogFilePath, o => o.Ignore())
                .ForMember(c => c.ValidateSignature, o => o.Ignore())
                .ForMember(c => c.PackagesList, o => o.Ignore())
                .ForMember(c => c.FilesList, o => o.Ignore())
                .ForMember(c => c.IgnoreMissing, o => o.Ignore());

            // Create config for the config json file to configuration.
            CreateMap<ConfigFile, InputConfiguration>()
                .ForMember(c => c.PackagesList, o => o.Ignore())
                .ForMember(c => c.FilesList, o => o.Ignore());

            // Add maps to combine both config json and argument args,
            // validate each settings using the config validator.
            CreateMap<InputConfiguration, InputConfiguration>();

            // Set value converters for each type of object.
            ForAllPropertyMaps(
                p => p.SourceType == typeof(string),
                (c, memberOptions) => memberOptions.ConvertUsing(new StringConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(bool?),
                (c, memberOptions) => memberOptions.ConvertUsing(new NullableBoolConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(bool),
                (c, memberOptions) => memberOptions.ConvertUsing(new BoolConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(int),
                (c, memberOptions) => memberOptions.ConvertUsing<int>(new IntConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(int?),
                (c, memberOptions) => memberOptions.ConvertUsing<int?>(new IntConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(LogEventLevel?),
                (c, memberOptions) => memberOptions.ConvertUsing(new LogEventLevelConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(IList<ManifestInfo>),
                (c, memberOptions) => memberOptions.ConvertUsing(new ManifestInfoConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
            ForAllPropertyMaps(
                p => p.SourceType == typeof(AlgorithmName),
                (c, memberOptions) => memberOptions.ConvertUsing(new HashAlgorithmNameConfigurationSettingAddingConverter(GetSettingSourceFor(c.SourceMember.ReflectedType))));
        }

        // Based on the type of source, return the settings type.
        private SettingSource GetSettingSourceFor(Type sourceType)
        {
            switch (sourceType)
            {
                case Type _ when sourceType.IsSubclassOf(typeof(CommonArgs)):
                case Type _ when sourceType == typeof(CommonArgs):
                    return SettingSource.CommandLine;
                case Type _ when sourceType == typeof(ConfigFile):
                    return SettingSource.JsonConfig;
                default: return SettingSource.Default;
            }
        }
    }
}