// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Common.Spdx30Entities;

/// <summary>
/// The SpdxDocument provides a convenient way to express information about collections of SPDX Elements that could potentially be serialized as complete units (e.g., all in-scope SPDX data within a single JSON-LD file).
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/SpdxDocument/
/// An NTIA SpdxDocument specifically describes a SpdxDocument entity compliant with the NTIA SBOM standard.
/// </summary>
public class NTIASpdxDocument : SpdxDocument
{
    public NTIASpdxDocument()
    {
        Type = nameof(SpdxDocument);
    }

    [JsonRequired]
    [JsonPropertyName("name")]
    public override string Name { get; set; }
}
