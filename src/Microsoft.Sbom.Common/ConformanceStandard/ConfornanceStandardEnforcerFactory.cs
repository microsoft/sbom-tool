// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.ComplianceStandard.Interfaces;

namespace Microsoft.Sbom.Common.ConformanceStandard;

public static class ConfornanceStandardEnforcerFactory
{
    public static IConformanceStandardEnforcer Create(ConformanceStandardType complianceStandard)
    {
        return complianceStandard.Name switch
        {
            "NTIA" => new NTIAConformanceStandardEnforcer(),
            "None" => new NoneConformanceStandardEnforcer(),
            _ => throw new ArgumentException($"Unsupported compliance standard: {complianceStandard.Name}")
        };
    }
}
