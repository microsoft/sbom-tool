// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Exceptions;

namespace Microsoft.Sbom.Api.Manifest
{
    /// <summary>
    /// Factory class that returns the correct implementation of the <see cref="IManifestGenerator"/>
    /// at runtime based on the 'ManifestInfo' parameter.
    /// </summary>
    public class ManifestGeneratorProvider
    {
        private readonly IManifestGenerator[] manifestGenerators;
        private readonly IDictionary<string, IManifestGenerator> manifestMap = new Dictionary<string, IManifestGenerator>(StringComparer.OrdinalIgnoreCase);

        public ManifestGeneratorProvider(IManifestGenerator[] manifestGenerators)
        {
            this.manifestGenerators = manifestGenerators ?? Array.Empty<IManifestGenerator>();
        }

        public void Init()
        {
            foreach (var manifestGenerator in manifestGenerators)
            {
                var manifestFormat = manifestGenerator.RegisterManifest();
                manifestMap[$"{manifestFormat.Name}:{manifestFormat.Version}"] = manifestGenerator;
            }
        }

        public IManifestGenerator Get(ManifestInfo manifestInfo)
        {
            var key = $"{manifestInfo.Name}:{manifestInfo.Version}";
            if(manifestMap.TryGetValue(key, out IManifestGenerator generator)) {
                return generator;
            }

            throw new MissingGeneratorException($"The SBOM format '{key}' is not supported by the SBOM tool");
        }

        public IEnumerable<ManifestInfo> GetSupportedManifestInfos()
        {
            var manifestInfoList = new List<ManifestInfo>();
            foreach (var miString in manifestMap.Keys)
            {
                manifestInfoList.Add(ManifestInfo.Parse(miString));
            }

            return manifestInfoList;
        }
    }
}
