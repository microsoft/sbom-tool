// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.Serialization;

namespace Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Represents the type of a file.
/// </summary>
public enum FileType
{
    /// <summary>
    /// The file is an SPDX type.
    /// </summary>
    [EnumMember(Value = "SPDX")]
    SPDX = 0,
}