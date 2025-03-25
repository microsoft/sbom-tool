// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;

namespace Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// A list of the names of the hash algorithms that are supported by this SBOM api.
/// We map to <see cref="HashAlgorithmName"/> for standard
/// hash algorithms.
/// </summary>
public class ComplianceStandardType : IEquatable<ComplianceStandardType>
{
    public string Name { get; set; }

    public ComplianceStandardType(string name)
    {
        Name = name;
    }

    public override string ToString()
    {
        return Name ?? string.Empty;
    }

    public static ComplianceStandardType FromString(string name)
    {
        if (string.IsNullOrEmpty(name) || string.Equals(name, None.Name, StringComparison.OrdinalIgnoreCase))
        {
            return None;
        }

        if (string.Equals(name, NTIA.Name, StringComparison.OrdinalIgnoreCase))
        {
            return NTIA;
        }

        throw new ArgumentException($"Unknown Compliance Standard '{name}'. Options are '{NTIA}'", nameof(name));
    }

    public override bool Equals(object obj)
    {
        return Equals(obj as ComplianceStandardType);
    }

    public bool Equals(ComplianceStandardType other)
    {
        if (other == null)
        {
            return false;
        }

        return string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);
    }

    public static ComplianceStandardType None => new ComplianceStandardType("None");

    public static ComplianceStandardType NTIA => new ComplianceStandardType("NTIA");

    public override int GetHashCode()
    {
        return Name == null ? 0 : Name.GetHashCode(StringComparison.OrdinalIgnoreCase);
    }
}
