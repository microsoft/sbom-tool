namespace Microsoft.Sbom.Parser.Strings;

internal readonly struct ExternalDocumentReferenceStrings
{
    public ExternalDocumentReferenceStrings()
    {
    }

    public const string GoodJsonWith2ExtDocumentRefsString = @"[
        {
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }},
        {
          ""externalDocumentId"": ""DocumentRef-Test-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/Test2"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d5dsfasdf3234f4f432gd23ds2f432f""
        }}]}";

    public const string JsonExtDocumentRefsStringMissingDocumentId = @"[{
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }}]";

    public const string JsonExtDocumentRefsStringMissingDocument = @"[{
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }}]";

    public const string JsonExtDocumentRefsStringMissingChecksum = @"[{
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug""]";

    public const string JsonExtDocumentRefsStringMissingSHA1Checksum = @"[{
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA256"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }}]";

    public const string JsonExtDocumentRefsStringAdditionalString = @"[
        {
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""additionalElement"": ""Additional value"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }}]";

    public const string JsonExtDocumentRefsStringAdditionalObject = @"[
        {
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
            },
          ""additionalProperty"": {
                    ""childAddtionalProperty"": ""Additional property value"" 
         }}]";

    public const string JsonExtDocumentRefsStringAdditionalArray = @"[
        {
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
          },
          ""additionalProperty"": [
                            {""childAddtionalProperty"": ""Additional property value"" }]
        }]";

    public const string JsonExtDocumentRefsStringAdditionalArrayNoKey = @"[
        {
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"": ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""additionalProperty"": [""Additional value 1"", ""Additional value 2""],
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }}]";

    public const string MalformedJson = @"[
        {
          ""externalDocumentId"": ""DocumentRef-LeftPad-1049-08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1"",
          ""spdxDocument"" ""https://sbom.microsoft/1:VF6zo7ndBEakT2mCbPwGug:mbFNG7JcLkCOpUAYBLp6Fw/28:1049/VUbyIvB6E0awQIFGAOI3Ug"",
          ""checksum"": {
            ""algorithm"": ""SHA1"",
            ""checksumValue"": ""08ec1a34d54ae4e28e8b3c4cf6c5c141e67d1af1""
        }}]";
}
