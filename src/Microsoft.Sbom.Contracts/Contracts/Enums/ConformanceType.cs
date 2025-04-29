// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// A list of the names of the hash algorithms that are supported by this SBOM api.
/// We map to <see cref="HashAlgorithmName"/> for standard
/// hash algorithms.
/// </summary>
public class ConformanceType : IEquatable<ConformanceType>
{
    public string Name { get; set; }

    public ConformanceType(string name)
    {
        Name = name;
    }

    public override string ToString()
    {
        return Name ?? string.Empty;
    }

    public static ConformanceType FromString(string name)
    {
        if (string.IsNullOrEmpty(name) || string.Equals(name, None.Name, StringComparison.OrdinalIgnoreCase))
        {
            return None;
        }

        if (string.Equals(name, NTIA.Name, StringComparison.OrdinalIgnoreCase))
        {
            return NTIA;
        }

        throw new ArgumentException($"Unknown Conformance Standard '{name}'.");
    }

    public override bool Equals(object obj)
    {
        return Equals(obj as ConformanceType);
    }

    public bool Equals(ConformanceType other)
    {
        if (other == null)
        {
            return false;
        }

        return string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);
    }

    public static ConformanceType None => new ConformanceType("None");

    public static ConformanceType NTIA => new ConformanceType("NTIA");

    public override int GetHashCode()
    {
        return Name == null ? 0 : Name.GetHashCode(StringComparison.OrdinalIgnoreCase);
    }
}
