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
      ""spdxId"": ""SPDXRef-Relationship-EA32E4936D0471CBA842A0F402ACC531203940676A148FEEF0377B7F99E7F284"",
      ""type"": ""Relationship""
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string RelationshipPrereqForJsonString =
    @"
    {
      ""from"": ""target-id"",
      ""relationshipType"": ""HAS_PREREQUISITE"",
      ""to"": [
        ""source-id""
      ],
      ""creationInfo"": ""_:creationinfo"",
      ""spdxId"": ""SPDXRef-Relationship-7915A144F583827985593DA51772D875C5B4F39A633050520EFC7996E55339DA"",
      ""type"": ""Relationship""
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string RelationshipDescribedByJsonString =
    @"
    {
      ""from"": ""target-id"",
      ""relationshipType"": ""DESCRIBES"",
      ""to"": [
        ""source-id""
      ],
      ""creationInfo"": ""_:creationinfo"",
      ""spdxId"": ""SPDXRef-Relationship-1FCAF439DB8C6907CAAB0B986079B3E53007B4A5E021F9F5A44F98675CC75EEA"",
      ""type"": ""Relationship""
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string RelationshipPatchForJsonString =
    @"
    {
      ""from"": ""target-id"",
      ""relationshipType"": ""PATCHED_BY"",
      ""to"": [
        ""source-id""
      ],
      ""creationInfo"": ""_:creationinfo"",
      ""spdxId"": ""SPDXRef-Relationship-3DD8A17F737548C21A881CE12FF3B87604CF5DBEDD5C5BEEA3B577FB3AA01DDC"",
      ""type"": ""Relationship""
    }
    ";
}
