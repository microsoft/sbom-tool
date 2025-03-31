// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common.ComplianceStandard.Enums;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.ComplianceStandard.Interfaces;

namespace Microsoft.Sbom.Common.ComplianceStandard;

public class InvalidElementInfo
{
    public InvalidElementInfo(IComplianceStandardErrorType errorType)
    {
        this.ErrorType = errorType;
    }

    public InvalidElementInfo(string name, string spdxId, IComplianceStandardErrorType errorType)
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
    public IComplianceStandardErrorType ErrorType { get; set; }

    public override string ToString()
    {
        if (this.ErrorType.Equals(NTIAErrorType.MissingValidCreationInfo))
        {
            return NTIAErrorType.MissingValidCreationInfo.ToString();
        }
        else if (this.ErrorType.Equals(NTIAErrorType.MissingValidSpdxDocument))
        {
            return NTIAErrorType.MissingValidSpdxDocument.ToString();
        }
        else if (this.ErrorType.Equals(NTIAErrorType.AdditionalSpdxDocument))
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
