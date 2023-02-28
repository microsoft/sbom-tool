// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using System;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Exceptions;

namespace Microsoft.Sbom.Api.Manifest
{
    /// <summary>
    /// Factory class that returns the correct implementation of the <see cref="IManifestGenerator"/>
    /// at runtime based on the 'ManifestInfo' parameter.
    /// </summary>
    public class ManifestGeneratorProvider
    {
        private readonly IEnumerable<IManifestGenerator> manifestGenerators;
        private readonly IDictionary<string, IManifestGenerator> manifestMap = new Dictionary<string, IManifestGenerator>(StringComparer.OrdinalIgnoreCase);

        public ManifestGeneratorProvider(IEnumerable<IManifestGenerator> manifestGenerators)
        {
            this.manifestGenerators = manifestGenerators ?? Array.Empty<IManifestGenerator>();

            Init();
        }

        public ManifestGeneratorProvider Init()
        {
            foreach (var manifestGenerator in manifestGenerators)
            {
                var manifestFormat = manifestGenerator.RegisterManifest();
                manifestMap[$"{manifestFormat.Name}:{manifestFormat.Version}"] = manifestGenerator;
            }

            return this;
        }

        public IManifestGenerator Get(ManifestInfo manifestInfo)
        {
            var key = $"{manifestInfo.Name}:{manifestInfo.Version}";
            if (manifestMap.TryGetValue(key, out IManifestGenerator generator))
            {
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
