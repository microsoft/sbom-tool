// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Output.Telemetry.Entities;

/// <summary>
/// Defines the telemetry we produce for each AggregationSource object
/// </summary>
public class AggregationSourceTelemetry
{
    public int PackageCount { get; set; }

    public int RelationShipCount { get; set; }
}
