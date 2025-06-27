// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common.Conformance.Enums;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Conformance.Interfaces;

namespace Microsoft.Sbom.Common.Conformance;

public class InvalidElementInfo
{
    public InvalidElementInfo(IConformanceErrorType errorType)
    {
        this.ErrorType = errorType;
    }

    public InvalidElementInfo(string name, string spdxId, IConformanceErrorType errorType)
    {
        this.Name = name;
        this.SpdxId = spdxId;
        this.ErrorType = errorType;
    }

    public string Name { get; set; }

    public string SpdxId { get; set; }

    /// <summary>
    /// The type of error that caused this element to be invalid.
    /// </summary>
    public IConformanceErrorType ErrorType { get; set; }

    public override string ToString()
    {
        if (this.ErrorType.Equals(NTIAMinErrorType.MissingValidCreationInfo))
        {
            return NTIAMinErrorType.MissingValidCreationInfo.ToString();
        }
        else if (this.ErrorType.Equals(NTIAMinErrorType.MissingValidSpdxDocument))
        {
            return NTIAMinErrorType.MissingValidSpdxDocument.ToString();
        }
        else if (this.ErrorType.Equals(NTIAMinErrorType.AdditionalSpdxDocument))
        {
            return $"AdditionalSpdxDocument. SpdxId: {this.SpdxId}. Name: {this.Name}";
        }
        else if (this.SpdxId == null && this.Name != null)
        {
            return $"Name: {this.Name}";
        }
        else if (this.SpdxId != null && this.Name == null)
        {
            return $"SpdxId: {this.SpdxId}";
        }
        else if (this.SpdxId != null && this.Name != null)
        {
            return $"SpdxId: {this.SpdxId}. Name: {this.Name}";
        }
        else
        {
            return string.Empty;
        }
    }
}
