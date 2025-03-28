// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Common.ComplianceStandard;

public class NoneComplianceStandardEnforcer : ComplianceStandardEnforcer
{
    public override ComplianceStandardType ComplianceStandard => ComplianceStandardType.None;

    public NoneComplianceStandardEnforcer() { }
}
