// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

using System.Text.Json.Serialization;

public class Range
{
    [JsonPropertyName("endPointer")]
    public Pointer EndPointer { get; set; }

    [JsonPropertyName("startPointer")]
    public Pointer StartPointer { get; set; }
}
