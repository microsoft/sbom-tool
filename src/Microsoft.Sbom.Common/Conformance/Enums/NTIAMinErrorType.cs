// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Conformance.Interfaces;

namespace Microsoft.Sbom.Common.Conformance.Enums;

public class NTIAMinErrorType : IConformanceErrorType, IEquatable<NTIAMinErrorType>
{
    public string Name { get; set; }

    public NTIAMinErrorType(string name)
    {
        Name = name;
    }

    public override string ToString()
    {
        return Name ?? string.Empty;
    }

    public override bool Equals(object obj)
    {
        return Equals(obj as NTIAMinErrorType);
    }

    public bool Equals(NTIAMinErrorType other)
    {
        if (other == null)
        {
            return false;
        }

        return string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);
    }

    public static NTIAMinErrorType InvalidNTIAMinElement => new NTIAMinErrorType("InvalidNTIAMinElement");

    public static NTIAMinErrorType MissingValidSpdxDocument => new NTIAMinErrorType("MissingValidSpdxDocument");

    public static NTIAMinErrorType AdditionalSpdxDocument => new NTIAMinErrorType("AdditionalSpdxDocument");

    public static NTIAMinErrorType MissingValidCreationInfo => new NTIAMinErrorType("MissingValidCreationInfo");

    public override int GetHashCode()
    {
        return Name == null ? 0 : Name.GetHashCode(StringComparison.OrdinalIgnoreCase);
    }
}
