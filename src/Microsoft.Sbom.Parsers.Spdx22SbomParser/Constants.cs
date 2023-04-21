// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser;

internal class Constants
{
    internal const string SPDXName = "SPDX";
    internal const string SPDXVersion = "2.2";
    internal const string DataLicenceValue = "CC0-1.0";
    internal const string SPDXDocumentIdValue = "SPDXRef-DOCUMENT";
    internal const string RootPackageIdValue = "SPDXRef-RootPackage";
    internal const string SPDXRefFile = "SPDXRef-File";
    #region Headers

    internal const string SPDXVersionHeaderName = "spdxVersion";
    internal const string DataLicenseHeaderName = "dataLicense";
    internal const string SPDXIDHeaderName = "SPDXID";
    internal const string DocumentNameHeaderName = "name";
    internal const string DocumentNamespaceHeaderName = "documentNamespace";
    internal const string CreationInfoHeaderName = "creationInfo";
    internal const string DocumentDescribesHeaderName = "documentDescribes";
        
    internal const string PackagesArrayHeaderName = "packages";
    internal const string FilesArrayHeaderName = "files";
    internal const string RelationshipsArrayHeaderName = "relationships";
    internal const string ExternalDocumentRefArrayHeaderName = "externalDocumentRefs";

    #endregion

    #region Value format strings

    internal const string SPDXDocumentNameFormatString = "{0} {1}";
    internal const string PackageSupplierFormatString = "Organization: {0}";

    #endregion

    /// <summary>
    /// Use if there is no available information for a field.
    /// </summary>
    internal const string NoneValue = "NONE";

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
    internal static List<string> NoAssertionListValue = new List<string> { NoAssertionValue };

    internal static ManifestInfo Spdx22ManifestInfo = new ManifestInfo
    {
        Name = Constants.SPDXName,
        Version = Constants.SPDXVersion
    };

    internal const int ReadBufferSize = 4096;

    /// <summary>
    /// Converts a <see cref="System.Text.Json.JsonTokenType"/> enum to the actual string
    /// representation of the token.
    /// </summary>
    internal static readonly string[] JsonTokenStrings = new string[]
    {
        string.Empty, // None
        "{", // StartObject
        "}", // EndObject
        "[", // StartArray
        "]", // EndArray
        "PropertyName", // PropertyName
        "Comment", // Comment
        "String", // String
        "Number", // Number
        "True", // True
        "False", // False
        "Null", // Null
    };
}