// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts.Enums;
using Serilog.Events;

namespace Microsoft.Sbom.Api.Utils
{
    public static class Constants
    {
        public const string ManifestFolder = "_manifest";

        

        public static ManifestInfo SPDX22ManifestInfo = new ManifestInfo
        {
            Name = "SPDX",
            Version = "2.2"
        };
           
        // TODO: move to test csproj
        public static ManifestInfo TestManifestInfo = new ManifestInfo
        {
            Name = "TestManifest",
            Version = "1.0.0"
        };

        public static AlgorithmName DefaultHashAlgorithmName = AlgorithmName.SHA256;

        public const string ManifestBsiFileName = "bsi.json";

        public const string SPDXFileExtension = ".spdx.json";
        public const string DocumentNamespaceString = "documentNamespace";
        public const string NameString = "name";
        public const string DocumentDescribesString = "documentDescribes";
        public const string SpdxVersionString = "spdxVersion";
        public const string DefaultRootElement = "SPDXRef-Document";
        public const string NamespaceUriBasePropertyName = "NamespaceUriBase";

        #region Configuration switches

        public const string DeleteManifestDirBoolVariableName = "DeleteManifestDirIfPresent";

        #endregion
    }
}
