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
        ""CopyrightText"": ""NOASSERTION"",
        ""software_downloadLocation"": ""NOASSERTION"",
        ""creationInfo"": ""_:creationinfo"",
        ""externalIdentifier"": [
            ""SPDXRef-ExternalIdentifier-CE6B7E4A59503594D0AF89492494E05071399F36D9085F1E722497D78A9404E1""
        ],
        ""name"": ""test"",
        ""spdxId"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
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
        ""name"": ""NoAssertion"",
        ""spdxId"": ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B"",
        ""type"": ""Element""
        },
        {
        ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
        ""relationshipType"": ""HAS_CONCLUDED_LICENSE"",
        ""to"": [
            ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-2A69D50DCB6D763C5C4FFCE6A4F6C3166DD8F6DB3F77BDD4B6129C0B33F238DA"",
        ""type"": ""Relationship""
        },
        {
        ""creationInfo"": ""_:creationinfo"",
        ""name"": ""NoAssertion"",
        ""spdxId"": ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B"",
        ""type"": ""Element""
        },
        {
        ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
        ""relationshipType"": ""HAS_DECLARED_LICENSE"",
        ""to"": [
            ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
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
        ""CopyrightText"": ""NOASSERTION"",
        ""software_downloadLocation"": ""NOASSERTION"",
        ""software_packageVersion"": ""the-package-version"",
        ""creationInfo"": ""_:creationinfo"",
        ""externalIdentifier"": [
          ""SPDXRef-ExternalIdentifier-.*""
        ],
        ""name"": ""the-package-name"",
        ""spdxId"": ""SPDXRef-software_Package-A8C9BE15D102D0AF9D34A9EAA6FE282AB0CE35FF48A83058703A964E512B68B7"",
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
        ""name"": ""NoAssertion"",
        ""spdxId"": ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B"",
        ""type"": ""Element""
      },
      {
        ""from"": ""SPDXRef-RootPackage"",
        ""relationshipType"": ""HAS_DECLARED_LICENSE"",
        ""to"": [
          ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
        ""type"": ""Relationship""
      },
      {
        ""from"": ""SPDXRef-RootPackage"",
        ""relationshipType"": ""HAS_CONCLUDED_LICENSE"",
        ""to"": [
          ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
        ],
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-Relationship-2A69D50DCB6D763C5C4FFCE6A4F6C3166DD8F6DB3F77BDD4B6129C0B33F238DA"",
        ""type"": ""Relationship""
      }
    ]";
}
