namespace Microsoft.Sbom.Parser.Strings;

internal readonly struct RelationshipStrings
{
    public RelationshipStrings()
    {
    }

    public const string GoodJsonWith2RelationshipsString = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"": ""SPDXRef-RootPackage""
            },
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-51F158669105E7517709DAA0BB58D31555101DE3988F1381C3501A7DD94042C7"",
              ""spdxElementId"": ""SPDXRef-RootPackage""
            }]";

    public const string JsonRelationshipsStringMissingElementId = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
            }]";

    public const string JsonRelationshipsStringMissingRelatedElement = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""spdxElementId"": ""SPDXRef-RootPackage""
            }]";

    public const string GoodJsonWithRelationshipsStringAdditionalString = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"": ""SPDXRef-RootPackage"",
              ""additionalElement"": ""Additional value""
            }]";

    public const string GoodJsonWithRelationshipsStringAdditionalObject = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"": ""SPDXRef-RootPackage"",
              ""additionalProperty"": {
                    ""childAddtionalProperty"": ""Additional property value"" 
                  }
            }]";

    public const string GoodJsonWithRelationshipsStringAdditionalArray = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"": ""SPDXRef-RootPackage"",
              ""additionalProperty"": [
                    {""childAddtionalProperty"": ""Additional property value"" }]
            }]";

    public const string GoodJsonWithRelationshipsStringAdditionalArrayNoKey = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"": ""SPDXRef-RootPackage"",
              ""additionalProperty"": [""Additional value 1"", ""Additional value 2""]
            }]";

    public const string MalformedJsonRelationshipsString = @"[
            {
              ""relationshipType"": ""DEPENDS_ON"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"" ""SPDXRef-RootPackage""
            }]";

    public const string MalformedJsonRelationshipsStringBadRelationshipType = @"[
            {
              ""relationshipType"": ""None"",
              ""relatedSpdxElement"": ""SPDXRef-Package-342BA5C11805FDDCAF3A2BF48BFDCAB5C0240793089F89196209A39C580902E6"",
              ""spdxElementId"": ""SPDXRef-RootPackage""
            }]";
}
