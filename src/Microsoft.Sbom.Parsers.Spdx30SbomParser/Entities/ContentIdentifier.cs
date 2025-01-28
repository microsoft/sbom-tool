// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// A ContentIdentifier is a canonical, unique, immutable identifier of the content of a software artifact, such as a package, a file, or a snippet.
/// It can be used for verifying its identity and integrity.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/ContentIdentifier/
/// </summary>
public class ContentIdentifier : Software
{
    private string contentIdentifierType;

    /// <summary>
    /// Gets or sets the content identifier type.
    /// Allowed types are Git Object ID and Software Hash Identifier (swhid).
    /// We will use swhid unless otherwise specified.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("contentIdentifierType")]
    public override string ContentIdentifierType
    {
        get => this.contentIdentifierType ?? "swhid";
        set => this.contentIdentifierType = value;
    }
}
