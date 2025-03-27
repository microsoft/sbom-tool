// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.ComplianceStandard.Interfaces;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.ComplianceStandard.Enums;

public class NTIAErrorType : IComplianceStandardErrorType, IEquatable<NTIAErrorType>
{
    public string Name { get; set; }

    public NTIAErrorType(string name)
    {
        Name = name;
    }

    public override string ToString()
    {
        return Name ?? string.Empty;
    }

    public override bool Equals(object obj)
    {
        return Equals(obj as NTIAErrorType);
    }

    public bool Equals(NTIAErrorType other)
    {
        if (other == null)
        {
            return false;
        }

        return string.Equals(Name, other.Name, StringComparison.OrdinalIgnoreCase);
    }

    public static NTIAErrorType InvalidNTIAElement => new NTIAErrorType("InvalidNTIAElement");

    public static NTIAErrorType MissingValidSpdxDocument => new NTIAErrorType("MissingValidSpdxDocument");

    public static NTIAErrorType AdditionalSpdxDocument => new NTIAErrorType("AdditionalSpdxDocument");

    public static NTIAErrorType MissingValidCreationInfo => new NTIAErrorType("MissingValidCreationInfo");

    public override int GetHashCode()
    {
        return Name == null ? 0 : Name.GetHashCode(StringComparison.OrdinalIgnoreCase);
    }
}
