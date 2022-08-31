// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts.Enums;
using Serilog.Events;

namespace Microsoft.Sbom.Api.Utils
{
    public static class Constants
    {
        public const int DefaultStreamBufferSize = 4096;

        public const int MinParallelism = 2;
        public const int DefaultParallelism = 8;
        public const int MaxParallelism = 48;

        public const LogEventLevel DefaultLogLevel = LogEventLevel.Warning;
        public const string ManifestFolder = "_manifest";
        public const string LoggerTemplate = "##[{Level:w}]{Message}{NewLine}{Exception}";

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

        public const string SPDXFileExtension = ".spdx.json";
        public const string DocumentNamespaceString = "documentNamespace";
        public const string NameString = "name";
        public const string DocumentDescribesString = "documentDescribes";
        public const string SpdxVersionString = "spdxVersion";
        public const string DefaultRootElement = "SPDXRef-Document";

        #region Configuration switches

        public const string DeleteManifestDirBoolVariableName = "DeleteManifestDirIfPresent";

        #endregion
    }
}
