// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomPackageJsonStrings
{
    public const string PackageWithNoAssertionAndPurlJsonString =
    /*lang=json,strict*/
    @"[
        {
        ""creationInfo"": ""_:creationinfo"",
        ""name"": ""NOASSERTION"",
        ""spdxId"": ""SPDXRef-Organization-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
        ""type"": ""Organization""
        },
        {
        ""suppliedBy"": ""SPDXRef-Organization-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
        ""name"": ""test"",
        ""software_copyrightText"": ""NOASSERTION"",
        ""software_downloadLocation"": ""NOASSERTION"",
        ""creationInfo"": ""_:creationinfo"",
        ""externalIdentifier"": [
            ""SPDXRef-ExternalIdentifier-CE6B7E4A59503594D0AF89492494E05071399F36D9085F1E722497D78A9404E1""
        ],
        ""spdxId"": ""SPDXRef-Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
        ""type"": ""software_Package""
        },
        {
        ""externalIdentifierType"": ""purl"",
        ""identifier"": ""packageUrl"",
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-ExternalIdentifier-CE6B7E4A59503594D0AF89492494E05071399F36D9085F1E722497D78A9404E1"",
        ""type"": ""ExternalIdentifier""
        },
        {
        ""creationInfo"": ""_:creationinfo"",
        ""name"": ""NOASSERTION"",
        ""spdxId"": ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
        ""type"": ""Element""
        },
        {
        ""from"": ""SPDXRef-Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
        ""relationshipType"": ""HAS_CONCLUDED_LICENSE"",
        ""to"": [
            ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-33966C6B2ACE7B56695E603E69AF055F95F60B74D1DDF3317A9EB3664A1830D3"",
        ""type"": ""Relationship""
        },
        {
        ""creationInfo"": ""_:creationinfo"",
        ""name"": ""NOASSERTION"",
        ""spdxId"": ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
        ""type"": ""Element""
        },
        {
        ""from"": ""SPDXRef-Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
        ""relationshipType"": ""HAS_DECLARED_LICENSE"",
        ""to"": [
            ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-094D0B898F06BDDC683C07EEE7C5D2D4C80F47AE22661F65513CF1A0EFF8556F"",
        ""type"": ""Relationship""
        }
    ]";

    public const string RootPackageJsonString =
    /*lang=json,strict*/
    @"[
      {
        ""externalIdentifierType"": ""purl"",
        ""identifier"": ""pkg:swid/the-package-supplier/sbom.microsoft/the-package-name@the-package-version?tag_id=.*"",
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-ExternalIdentifier-.*"",
        ""type"": ""ExternalIdentifier""
      },
      {
        ""creationInfo"": ""_:creationinfo"",
        ""name"": ""Organization: the-package-supplier"",
        ""spdxId"": ""SPDXRef-Organization-D914F48404CB6C27373666F70709BABF08C6603E1303B97758A20190A050CE16"",
        ""type"": ""Organization""
      },
      {
        ""name"": ""the-package-name"",
        ""software_copyrightText"": ""NOASSERTION"",
        ""software_downloadLocation"": ""NOASSERTION"",
        ""software_packageVersion"": ""the-package-version"",
        ""creationInfo"": ""_:creationinfo"",
        ""externalIdentifier"": [
          ""SPDXRef-ExternalIdentifier-.*""
        ],
        ""spdxId"": ""SPDXRef-RootPackage"",
        ""verifiedUsing"": [
          {
            ""algorithm"": ""sha1"",
            ""hashValue"": ""da39a3ee5e6b4b0d3255bfef95601890afd80709"",
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
            ""type"": ""PackageVerificationCode""
          }
        ],
        ""type"": ""software_Package""
      },
      {
        ""creationInfo"": ""_:creationinfo"",
        ""name"": ""NOASSERTION"",
        ""spdxId"": ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
        ""type"": ""Element""
      },
      {
        ""from"": ""SPDXRef-RootPackage"",
        ""relationshipType"": ""HAS_DECLARED_LICENSE"",
        ""to"": [
          ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-7DF43F21BD7F09FB8F3B2D0E77A6A7F8BF42588FA2602BF0A6BD8FC1A3F284B2"",
        ""type"": ""Relationship""
      },
      {
        ""from"": ""SPDXRef-RootPackage"",
        ""relationshipType"": ""HAS_CONCLUDED_LICENSE"",
        ""to"": [
          ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-0D5D61E52301E1C0B515E7719E4A236A45089872763C39D9DA40AB21EEEC39E2"",
        ""type"": ""Relationship""
      }
    ]";
}
