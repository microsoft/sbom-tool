// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

using System.Text.Json.Serialization;

/// <summary>
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Classes/NamespaceMap/
/// </summary>
public class NamespaceMap : Element
{
   public NamespaceMap()
   {
        Type = "NamespaceMap";
   }

   [JsonRequired]
   [JsonPropertyName("namespace")]
   public string Namespace { get; set; }
}
