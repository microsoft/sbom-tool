// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomRelationshipJsonStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string RelationshipJsonString =
    @"
    {
      ""from"": ""source-id"",
      ""relationshipType"": ""DESCRIBES"",
      ""to"": [
        ""target-id""
      ],
      ""creationInfo"": ""_:creationinfo"",
      ""spdxId"": ""SPDXRef-Relationship-4A4165C4543F807E438AC18B09585043D3F49095D996BC098C74EC358AD24558"",
      ""type"": ""Relationship""
    }
    ";
}
