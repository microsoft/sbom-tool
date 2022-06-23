// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using System;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Recorder;
using Microsoft.Sbom.Common;
using Constants = Microsoft.Sbom.Api.Utils.Constants;

namespace Microsoft.Sbom.Api.Manifest.ManifestConfigHandlers
{
    /// <summary>
    /// Provides the ManifestConfig for the SPDX 2.2 format.
    /// </summary>
    public class SPDX22ManifestConfigHandler : IManifestConfigHandler
    {
        private readonly IConfiguration configuration;
        private readonly IFileSystemUtils fileSystemUtils;
        private readonly IMetadataBuilder metadataBuilder;

        private readonly string sbomDirPath;
        private readonly string sbomFilePath;

        public SPDX22ManifestConfigHandler(
            IConfiguration configuration,
            IFileSystemUtils fileSystemUtils,
            IMetadataBuilderFactory metadataBuilderFactory)
        {
            if (metadataBuilderFactory is null)
            {
                throw new ArgumentNullException(nameof(metadataBuilderFactory));
            }

            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));

            string manifestDirPath = configuration.ManifestDirPath.Value;

            // directory path for SPDX 2.2 is 
            // root/_manifest/spdx_2.2/
            sbomDirPath = fileSystemUtils.JoinPaths(manifestDirPath, $"{Constants.SPDX22ManifestInfo.Name.ToLower()}_{Constants.SPDX22ManifestInfo.Version.ToLower()}");

            // sbom file path is manifest.spdx.json in the sbom directory.
            sbomFilePath = fileSystemUtils.JoinPaths(sbomDirPath, $"manifest.{Constants.SPDX22ManifestInfo.Name.ToLower()}.json");

            metadataBuilder = metadataBuilderFactory.Get(Constants.SPDX22ManifestInfo);
        }

        public bool TryGetManifestConfig(out ISbomConfig sbomConfig)
        {
            sbomConfig = new SbomConfig(fileSystemUtils)
            {
                ManifestInfo = Constants.SPDX22ManifestInfo,
                ManifestJsonDirPath = sbomDirPath,
                ManifestJsonFilePath = sbomFilePath,
                MetadataBuilder = metadataBuilder,
                Recorder = new SbomPackageDetailsRecorder()
            };

            // For generation the default behavior is to always return true
            // as we generate all the current formats of SBOM. Only override if the -mi 
            // argument is specified.
            if (configuration.ManifestToolAction == ManifestToolActions.Generate)
            {
                if (configuration.ManifestInfo?.Value != null
                    && !configuration.ManifestInfo.Value.Contains(Constants.SPDX22ManifestInfo))
                {
                    return false;
                }

                return true;
            }

            if (configuration.ManifestToolAction == ManifestToolActions.Validate
               && fileSystemUtils.FileExists(sbomFilePath))
            {
                // Even if we find a valid SPDX 2.2 SBOM, we should not return
                // the SPDX validator as it is not implemented yet.
                sbomConfig = null;
                return false;
            }

            sbomConfig = null;
            return false;
        }
    }
}
