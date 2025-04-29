// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Conformance.Interfaces;

namespace Microsoft.Sbom.Common.Conformance;

public static class ConfornanceEnforcerFactory
{
    public static IConformanceEnforcer Create(ConformanceType conformance)
    {
        return conformance.Name switch
        {
            "NTIA" => new NTIAConformanceEnforcer(),
            "None" => new NoneConformanceEnforcer(),
            _ => throw new ArgumentException($"Unsupported conformance standard: {conformance.Name}")
        };
    }
}
