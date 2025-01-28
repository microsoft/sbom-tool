// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Class defintion is based on: https://spdx.github.io/spdx-spec/v3.0.1/model/SimpleLicensing/Classes/AnyLicenseInfo/
/// </summary>
public class AnyLicenseInfo : Element
{
    public AnyLicenseInfo()
    {
        SpdxId = "SPDXRef-AnyLicenseInfo";
    }
}
