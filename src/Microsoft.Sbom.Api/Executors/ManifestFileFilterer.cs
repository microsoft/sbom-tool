﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Ninject;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Filters out files in the manifest.json that are not present on the disk and shouldn't
    /// be checked as specified by the root path filter parameter.
    /// </summary>
    public class ManifestFileFilterer
    {
        private readonly ManifestData manifestData;
        private readonly IFilter rootPathFilter;
        private readonly IConfiguration configuration;
        private readonly ILogger log;
        private readonly IFileSystemUtils fileSystemUtils;

        public ManifestFileFilterer(
            ManifestData manifestData,
            [Named(nameof(DownloadedRootPathFilter))]
            IFilter rootPathFilter,
            IConfiguration configuration,
            ILogger log,
            IFileSystemUtils fileSystemUtils)
        {
            this.manifestData = manifestData ?? throw new ArgumentNullException(nameof(manifestData));
            this.rootPathFilter = rootPathFilter ?? throw new ArgumentNullException(nameof(rootPathFilter));
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.log = log ?? throw new ArgumentNullException(nameof(log));
            this.fileSystemUtils = fileSystemUtils;
        }

        public ChannelReader<FileValidationResult> FilterManifestFiles()
        {
            var errors = Channel.CreateUnbounded<FileValidationResult>();

            Task.Run(async () =>
            {
                var manifestKeys = manifestData.HashesMap != null
                                        ? new List<string>(manifestData.HashesMap.Keys)
                                        : new List<string>();

                foreach (var manifestFile in manifestKeys)
                {
                    try
                    {
                        string file = fileSystemUtils.JoinPaths(configuration.BuildDropPath.Value, manifestFile);
                        if (!rootPathFilter.IsValid(file))
                        {
                            // This path is filtered, remove from the manifest map.
                            manifestData.HashesMap.Remove(manifestFile);

                            await errors.Writer.WriteAsync(new FileValidationResult
                            {
                                ErrorType = ErrorType.FilteredRootPath,
                                Path = manifestFile
                            });
                        }
                    }
                    catch (Exception e)
                    {
                        log.Debug($"Encountered an error while filtering file {manifestFile} from the manifest: {e.Message}");
                        await errors.Writer.WriteAsync(new FileValidationResult
                        {
                            ErrorType = ErrorType.Other,
                            Path = manifestFile
                        });
                    }
                }

                errors.Writer.Complete();
            });

            return errors;
        }
    }
}
