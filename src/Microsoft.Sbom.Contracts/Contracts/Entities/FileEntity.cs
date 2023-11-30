// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts.Entities;

/// <summary>
/// Represents a single file in a SBOM.
/// </summary>
public class FileEntity : Entity
{
    /// <summary>
    /// Gets the path of the file as included in the SBOM.
    /// </summary>
    public string Path { get; private set; }

    /// <nodoc />
    public FileEntity(string path, string id = null)
        : base(EntityType.File, id)
    {
        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentException($"'{nameof(path)}' cannot be null or empty.", nameof(path));
        }

        Path = path;
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return $"FileEntity (Path={Path}{(Id == null ? string.Empty : $", Id={Id}")})";
    }
}
