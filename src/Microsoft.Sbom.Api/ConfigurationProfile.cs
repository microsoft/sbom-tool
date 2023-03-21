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
            CreateMap<ValidationArgs, Configuration>()
#pragma warning disable CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(nameof(Configuration.ManifestPath), o => o.Ignore())
#pragma warning restore CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(nameof(Configuration.PackageName), o => o.Ignore())
                .ForMember(nameof(Configuration.PackageVersion), o => o.Ignore())
                .ForMember(nameof(Configuration.BuildListFile), o => o.Ignore())
                .ForMember(nameof(Configuration.ExternalDocumentReferenceListFile), o => o.Ignore())
                .ForMember(nameof(Configuration.BuildComponentPath), o => o.Ignore())
                .ForMember(nameof(Configuration.PackagesList), o => o.Ignore())
                .ForMember(nameof(Configuration.FilesList), o => o.Ignore())
                .ForMember(nameof(Configuration.DockerImagesToScan), o => o.Ignore())
                .ForMember(nameof(Configuration.AdditionalComponentDetectorArgs), o => o.Ignore())
                .ForMember(nameof(Configuration.GenerationTimestamp), o => o.Ignore())
                .ForMember(nameof(Configuration.NamespaceUriUniquePart), o => o.Ignore())
                .ForMember(nameof(Configuration.NamespaceUriBase), o => o.Ignore())
                .ForMember(nameof(Configuration.DeleteManifestDirIfPresent), o => o.Ignore())
                .ForMember(nameof(Configuration.PackageSupplier), o => o.Ignore());

            // Create config for the generation args, ignoring other action members
            CreateMap<GenerationArgs, Configuration>()
#pragma warning disable CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(nameof(Configuration.ManifestPath), o => o.Ignore())
#pragma warning restore CS0618 // 'Configuration.ManifestPath' is obsolete: 'This field is not provided by the user or configFile, set by system'
                .ForMember(nameof(Configuration.OutputPath), o => o.Ignore())
                .ForMember(nameof(Configuration.HashAlgorithm), o => o.Ignore())
                .ForMember(nameof(Configuration.RootPathFilter), o => o.Ignore())
                .ForMember(nameof(Configuration.CatalogFilePath), o => o.Ignore())
                .ForMember(nameof(Configuration.ValidateSignature), o => o.Ignore())
                .ForMember(nameof(Configuration.PackagesList), o => o.Ignore())
                .ForMember(nameof(Configuration.FilesList), o => o.Ignore())
                .ForMember(nameof(Configuration.IgnoreMissing), o => o.Ignore());

            // Create config for the config json file to configuration.
            CreateMap<ConfigFile, Configuration>()
                .ForMember(nameof(Configuration.PackagesList), o => o.Ignore())
                .ForMember(nameof(Configuration.FilesList), o => o.Ignore());

            // Add maps to combine both config json and argument args,
            // validate each settings using the config validator.
            CreateMap<Configuration, Configuration>()
                    .AfterMap<ConfigPostProcessor>()
                    .ForAllMembers(dest => dest.Condition((src, dest, srcObj, dstObj) =>
                    {
                        // If the property is set in both source and destination (config and cmdline),
                        // this is a failure case, unless one of the property is a default value, in which
                        // case the non default value wins.
                        if (srcObj != null && dstObj != null
                            && srcObj is ISettingSourceable srcWithSource
                            && dstObj is ISettingSourceable dstWithSource)
                        {
                            if (srcWithSource.Source != SettingSource.Default && dstWithSource.Source != SettingSource.Default)
                            {
                                throw new Exception($"Duplicate keys found in config file and command line parameters.");
                            }

                            return dstWithSource.Source == SettingSource.Default;
                        }

                        // If source property is not null, use source, or else use destination value.
                        return srcObj != null;
                    }));

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