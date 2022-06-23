// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Ninject;
using Ninject.Activation;
using System.Collections.Concurrent;
using Microsoft.Sbom.Common.Config;
using System.Linq;

namespace Microsoft.Sbom.Api.Manifest
{
    /// <summary>
    /// Provides the <see cref="ManifestData"/> from a given manifest file.
    /// </summary>
    public class ManifestDataProvider : Provider<ManifestData>
    {
        private readonly IFileSystemUtils fileSystemUtils;
        private readonly IOSUtils osUtils;
        private readonly ISbomConfigProvider sbomConfigs;
        private readonly IConfiguration configuration;

        public ManifestDataProvider(IFileSystemUtils fileSystemUtils, ISbomConfigProvider sbomConfigs, IOSUtils osUtils, IConfiguration configuration)
        {
            this.fileSystemUtils = fileSystemUtils ?? throw new System.ArgumentNullException(nameof(fileSystemUtils));
            this.sbomConfigs = sbomConfigs ?? throw new System.ArgumentNullException(nameof(sbomConfigs));
            this.osUtils = osUtils ?? throw new System.ArgumentNullException(nameof(osUtils));
            this.configuration = configuration ?? throw new System.ArgumentNullException(nameof(configuration));
        }

        /// <summary>
        /// Uses the manifest parser provider to select the correct parser.
        /// Converts the dictionary inside the <see cref="ManifestData"/> into a case insensitive
        /// concurrent dictionary.
        /// </summary>
        /// 
        /// <param name="context"></param>
        /// <returns></returns>
        protected override ManifestData CreateInstance(IContext context)
        {
            var sbomConfig = sbomConfigs.Get(configuration.ManifestInfo?.Value?.FirstOrDefault());
            var parserProvider = context.Kernel.Get<ManifestParserProvider>();
            var manifestValue = fileSystemUtils.ReadAllText(sbomConfig.ManifestJsonFilePath);
            var manifestData = parserProvider.Get(sbomConfig.ManifestInfo).ParseManifest(manifestValue);
            manifestData.HashesMap = new ConcurrentDictionary<string, Checksum[]>(manifestData.HashesMap, osUtils.GetFileSystemStringComparer());

            return manifestData;
        }
    }
}
