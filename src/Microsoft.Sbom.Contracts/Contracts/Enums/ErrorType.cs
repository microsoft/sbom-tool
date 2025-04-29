// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.Serialization;

namespace Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// The type of <see cref="EntityError"/> for a given entity.
/// </summary>
public enum ErrorType
{
    /// <summary>
    /// No error was detected.
    /// </summary>
    [EnumMember(Value = "None")]
    None = 0,

    /// <summary>
    /// An error was encountered when hashing a file.
    /// </summary>
    [EnumMember(Value = "Hashing error")]
    HashingError = 1,

    /// <summary>
    /// The SBOM generation doesn't have permissions to access a resource.
    /// </summary>
    [EnumMember(Value = "Permissions error")]
    PermissionsError = 2,

    /// <summary>
    /// The package is invalid.
    /// </summary>
    [EnumMember(Value = "Package error")]
    PackageError = 3,

    /// <summary>
    /// The file is invalid.
    /// </summary>
    [EnumMember(Value = "File error")]
    FileError = 4,

    /// <summary>
    /// Error while serializing JSON.
    /// </summary>
    [EnumMember(Value = "Json serialization error")]
    JsonSerializationError = 5,

    /// <summary>
    /// Element does not meet compliance standard.
    /// </summary>
    [EnumMember(Value = "Conformance standard validation error")]
    ConformanceStandardError = 6,

    /// <summary>
    /// An unknown error occured.
    /// </summary>
    [EnumMember(Value = "Other")]
    Other = 255,
}
