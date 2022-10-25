// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using System;
using System.IO;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser
{
    /// <summary>
    /// Validates files in a folder against their checksums stored in an SPDX 2.2 SBOM. 
    /// </summary>
    public class Validator : IManifestInterface
    {
        public string Version { get; set; }

        private readonly ManifestInfo spdxManifestInfo = new ManifestInfo
        {
            Name = Constants.SPDXName,
            Version = Constants.SPDXVersion
        };

        public ManifestData ParseManifest(string manifest)
        {
            throw new NotImplementedException($"Currently we don't support parsing complete SPDX 2.2 SBOMs");
        }

        public ManifestInfo[] RegisterManifest() => new[] { spdxManifestInfo };

        public ISbomParser CreateParser(Stream stream)
        {
            return new SPDXParser(stream);
        }
    }
}
