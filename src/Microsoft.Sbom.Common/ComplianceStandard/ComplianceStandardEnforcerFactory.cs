// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.ComplianceStandard.Interfaces;

namespace Microsoft.Sbom.Common.ComplianceStandard;

public static class ComplianceStandardEnforcerFactory
{
    public static IComplianceStandardEnforcer Create(ComplianceStandardType complianceStandard)
    {
        return complianceStandard.Name switch
        {
            "NTIA" => new NTIAComplianceStandardEnforcer(),
            "None" => new NoneComplianceStandardEnforcer(),
            _ => throw new ArgumentException($"Unsupported compliance standard: {complianceStandard.Name}")
        };
    }
}
