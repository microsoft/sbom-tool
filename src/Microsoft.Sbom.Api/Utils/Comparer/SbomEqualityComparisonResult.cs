// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Utils.Comparer;

/// <summary>
/// Represents the result of comparing SPDX 2.2 and SPDX 3.0 SBOM's.
/// </summary>
public enum SbomEqualityComparisonResult
{
    /// <summary>
    /// Documents are equal.
    /// </summary>
    Equal = 0,

    /// <summary>
    /// External document references are not equal.
    /// </summary>
    ExternalDocumentReferencesNotEqual,

    /// <summary>
    /// Relationships between elements are not equal.
    /// </summary>
    RelationshipsNotEqual,

    /// <summary>
    /// Files in the documents are not equal.
    /// </summary>
    FilesNotEqual,

    /// <summary>
    /// Packages in the documents are not equal.
    /// </summary>
    PackagesNotEqual,

    /// <summary>
    /// Count of external document references does not match.
    /// </summary>
    ExternalDocumentReferenceCountMismatch,

    /// <summary>
    /// Count of relationships does not match.
    /// </summary>
    RelationshipCountMismatch,

    /// <summary>
    /// Count of files does not match.
    /// </summary>
    FileCountMismatch,

    /// <summary>
    /// Count of packages does not match.
    /// </summary>
    PackageCountMismatch
}
