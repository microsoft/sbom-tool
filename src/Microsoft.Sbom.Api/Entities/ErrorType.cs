// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Entities;

/// <summary>
/// Type of validation error for a given file.
/// </summary>
public enum ErrorType
{
    [EnumMember(Value = "None")]
    None = 0,

    [EnumMember(Value = "Invalid Hash")]
    InvalidHash = 1,

    [EnumMember(Value = "Additional File")]
    AdditionalFile = 2,

    [EnumMember(Value = "Missing File")]
    MissingFile = 3,

    [EnumMember(Value = "Filtered root path")]
    FilteredRootPath = 4,

    [EnumMember(Value = "Manifest folder")]
    ManifestFolder = 5,

    [EnumMember(Value = "Other")]
    Other = 6,

    [EnumMember(Value = "Package error")]
    PackageError = 7,

    [EnumMember(Value = "Json serialization error")]
    JsonSerializationError = 8,

    [EnumMember(Value = "Unsupported hash algorithm")]
    UnsupportedHashAlgorithm = 9,

    [EnumMember(Value = "Referenced SBOM file")]
    ReferencedSbomFile = 10,

    [EnumMember(Value = "No packages found")]
    NoPackagesFound = 11
}