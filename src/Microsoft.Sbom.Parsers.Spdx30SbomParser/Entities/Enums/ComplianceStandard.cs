// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;

/// <summary>
/// Defines the different supported compliance standards.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ComplianceStandard
{
    NTIA,
    None,
}
