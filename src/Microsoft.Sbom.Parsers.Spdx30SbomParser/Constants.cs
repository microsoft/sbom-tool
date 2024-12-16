// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions.Entities;

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

    /// <summary>
    /// Use if SPDX creator
    /// - made an attempt to retrieve the info but cannot determine correct values.
    /// - made no attempt to retrieve the info.
    /// - has intentionally provided no information.
    /// </summary>
    internal const string NoAssertionValue = "NOASSERTION";

    /// <summary>
    /// The <see cref="NoAssertionValue"/> value as a list with a single item.
    /// </summary>
    internal static IEnumerable<string> NoAssertionListValue = new List<string> { NoAssertionValue };

    internal static ManifestInfo Spdx30ManifestInfo = new ManifestInfo
    {
        Name = SPDXName,
        Version = SPDXVersion
    };
}
