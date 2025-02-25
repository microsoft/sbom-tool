// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using HashAlgorithm = Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums.HashAlgorithm;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser;

internal static class Constants
{
    internal const string SPDXName = "SPDX";
    internal const string SPDXVersion = "3.0";
    internal const string DataLicenceValue = "CC0-1.0";
    internal const string SPDXDocumentIdValue = "SPDXRef-DOCUMENT";
    internal const string RootPackageIdValue = "SPDXRef-RootPackage";
    internal const string SPDXDocumentNameFormatString = "{0} {1}";
    internal const string PackageSupplierFormatString = "Organization: {0}";
    internal const string SPDXContextHeaderName = "@context";
    internal const string SPDXGraphHeaderName = "@graph";
    internal const string SPDXVersionHeaderName = "spdxVersion";
    internal const string DataLicenseHeaderName = "dataLicense";
    internal const string SPDXIDHeaderName = "SPDXID";
    internal const string DocumentNameHeaderName = "name";
    internal const string DocumentNamespaceHeaderName = "documentNamespace";
    internal const string CreationInfoHeaderName = "creationInfo";
    internal const string DocumentDescribesHeaderName = "documentDescribes";

    /// <summary>
    /// Use if SPDX creator
    /// - made an attempt to retrieve the info but cannot determine correct values.
    /// - made no attempt to retrieve the info.
    /// - has intentionally provided no information.
    /// </summary>
    internal const string NoAssertionValue = "NOASSERTION";

    internal const int ReadBufferSize = 4096;

    /// <summary>
    /// The <see cref="NoAssertionValue"/> value as a list with a single item.
    /// </summary>
    internal static IEnumerable<string> NoAssertionListValue = new List<string> { NoAssertionValue };

    internal static ManifestInfo SPDX30ManifestInfo = new ManifestInfo
    {
        Name = SPDXName,
        Version = SPDXVersion
    };

    public static readonly Dictionary<AlgorithmName, HashAlgorithm> AlgorithmMap = new()
    {
        { AlgorithmName.SHA1, HashAlgorithm.sha1 },
        { AlgorithmName.SHA256, HashAlgorithm.sha256 },
        { AlgorithmName.SHA512, HashAlgorithm.sha512 },
        { AlgorithmName.MD5, HashAlgorithm.md5 }
    };
}
