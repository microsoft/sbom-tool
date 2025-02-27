// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Extensions.Entities;

/// <summary>
/// Defines a manifest name and version.
/// </summary>
public class ManifestInfo : IEquatable<ManifestInfo>
{
    /// <summary>
    /// Gets or sets the name of the manifest.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Gets or sets the version of the manifest.
    /// </summary>
    public string Version { get; set; }

    /// <summary>
    /// Parses the manifest info from a string
    /// The format is <code>&lt;name&gt;:&lt;version&gt;</code>
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public static ManifestInfo Parse(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ArgumentException($"The manifest info string is empty");
        }

        var values = value.Split(':');
        if (values == null || values.Length != 2)
        {
            throw new ArgumentException($"The manifest info string is not formatted correctly. The correct format is <name>:<version>.");
        }

        return new ManifestInfo
        {
            Name = values[0],
            Version = values[1]
        };
    }

    public override bool Equals(object obj)
    {
        return Equals(obj as ManifestInfo);
    }

    public static bool operator ==(ManifestInfo obj1, ManifestInfo obj2)
    {
        if (ReferenceEquals(obj1, obj2))
        {
            return true;
        }

        if (obj1 is null || obj2 is null)
        {
            return false;
        }

        return obj1.Equals(obj2);
    }

    public static bool operator !=(ManifestInfo obj1, ManifestInfo obj2) => !(obj1 == obj2);

    public override int GetHashCode()
    {
        var hashCode = 2112831277;
        hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(Name.ToLowerInvariant());
        hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(Version.ToLowerInvariant());
        return hashCode;
    }

    public bool Equals(ManifestInfo other)
    {
        return Name.ToLowerInvariant() == other.Name.ToLowerInvariant() &&
               Version.ToLowerInvariant() == other.Version.ToLowerInvariant();
    }

    public override string ToString()
    {
        return $"{Name}:{Version}";
    }

    public string ToLowerString()
    {
        return $"{Name.ToLowerInvariant()}:{Version.ToUpperInvariant()}";
    }

    /// <summary>
    /// Converts a <see cref="ManifestInfo"/> to a <see cref="SbomSpecification"/> object.
    /// </summary>
    /// <param name="manifestInfo"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static SbomSpecification ToSBOMSpecification(ManifestInfo manifestInfo)
    {
        if (manifestInfo is null)
        {
            throw new ArgumentNullException(nameof(manifestInfo));
        }

        return new SbomSpecification(manifestInfo.Name, manifestInfo.Version);
    }
}
