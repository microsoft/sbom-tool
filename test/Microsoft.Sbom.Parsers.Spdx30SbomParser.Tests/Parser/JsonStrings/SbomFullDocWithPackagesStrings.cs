// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomFullDocWithPackagesStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomPackageWithMissingVerificationJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
                ""relationshipType"": ""HAS_DECLARED_LICENSE"",
                ""to"": [
                    ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
                ],
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
                ""type"": ""Relationship""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomPackageWithMissingSHA256JsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""verifiedUsing"": [
                    {
                    ""algorithm"": ""sha1"",
                    ""hashValue"": ""sha1value"",
                    ""creationInfo"": ""_:creationinfo"",
                    ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                    ""type"": ""PackageVerificationCode""
                    }
                ],
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
                ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
                ""relationshipType"": ""HAS_DECLARED_LICENSE"",
                ""to"": [
                    ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
                ],
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
                ""type"": ""Relationship""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomNTIAValidPackageJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""verifiedUsing"": [
                    {
                        ""algorithm"": ""sha1"",
                        ""hashValue"": ""sha1value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    },
                    {
                        ""algorithm"": ""sha256"",
                        ""hashValue"": ""sha256value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-A1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    }
                ],
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
                ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
                ""relationshipType"": ""HAS_DECLARED_LICENSE"",
                ""to"": [
                    ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
                ],
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
                ""type"": ""Relationship""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomPackageWithMissingNameJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""NOASSERTION"",
                ""spdxId"": ""SPDXRef-Organization-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
                ""type"": ""Organization""
            },
            {
                ""suppliedBy"": ""SPDXRef-Organization-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
                ""software_copyrightText"": ""NOASSERTION"",
                ""software_downloadLocation"": ""NOASSERTION"",
                ""creationInfo"": ""_:creationinfo"",
                ""externalIdentifier"": [
                    ""SPDXRef-ExternalIdentifier-CE6B7E4A59503594D0AF89492494E05071399F36D9085F1E722497D78A9404E1""
                ],
                ""verifiedUsing"": [
                    {
                        ""algorithm"": ""sha1"",
                        ""hashValue"": ""sha1value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    },
                    {
                        ""algorithm"": ""sha256"",
                        ""hashValue"": ""sha256value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-A1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    }
                ],
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
                ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
                ""relationshipType"": ""HAS_DECLARED_LICENSE"",
                ""to"": [
                    ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
                ],
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
                ""type"": ""Relationship""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomPackageWithMissingSpdxIdJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""verifiedUsing"": [
                    {
                        ""algorithm"": ""sha1"",
                        ""hashValue"": ""sha1value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    },
                    {
                        ""algorithm"": ""sha256"",
                        ""hashValue"": ""sha256value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-A1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    }
                ],
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
                ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
                ""relationshipType"": ""HAS_DECLARED_LICENSE"",
                ""to"": [
                    ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
                ],
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
                ""type"": ""Relationship""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""type"": ""SpdxDocument""
            }   
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomPackageWithAdditionalPropertiesJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""verifiedUsing"": [
                    {
                        ""algorithm"": ""sha1"",
                        ""hashValue"": ""sha1value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    },
                    {
                        ""algorithm"": ""sha256"",
                        ""hashValue"": ""sha256value"",
                        ""creationInfo"": ""_:creationinfo"",
                        ""spdxId"": ""SPDXRef-PackageVerificationCode-A1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                        ""type"": ""PackageVerificationCode""
                    }
                ],
                ""spdxId"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",    
                ""type"": ""software_Package"",
                ""additionalProperty"": ""additionalValue"",
                ""additionalPropertyArray"": [""additionalValue1"", ""additionalValue2""],
                ""additionalPropertyObject"": {""additionalPropertyObjectKey"": ""additionalPropertyObjectValue""},
                ""additionalPropertyWithArrayChildProperty"": [
                    {""childAddtionalProperty"": ""Additional property value""}
                ],
                ""additionalPropertyWithObjectChildProperty"": {
                    ""childAddtionalProperty"": ""Additional property value""
                }
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
                ""from"": ""SPDXRef-software_Package-4739C82D88855A138C811B8CE05CC97113BEC7F7C7F66EC7E4C6C176EEA0FECE"",
                ""relationshipType"": ""HAS_DECLARED_LICENSE"",
                ""to"": [
                    ""SPDXRef-Element-D6D57C0C9CC2CAC35C83DE0C8E4C8C37B87C0A58DA49BB31EBEBC6E200F54D4B""
                ],
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
                ""type"": ""Relationship""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft"",
                ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
                ""type"": ""Organization""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""Microsoft.SBOMTool-3.0.2-preview.0.41"",
                ""spdxId"": ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA"",
                ""type"": ""Tool""
            },
            {
                ""@id"": ""_:creationinfo"",
                ""created"": ""2023-05-11T00:24:54Z"",
                ""createdBy"": [
                    ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
                ],
                ""createdUsing"": [
                    ""SPDXRef-Tool-F3816A2B734CA08686741B17A8BC9020B8513FCE6A7BD33B1006102E2A1B55AA""
                ],
                ""specVersion"": ""3.0"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-CreationInfo-0799B4D592549CF6159C30BA3E278BF063A6A241B8728C18E7AEC18BFC2CFF6F"",
                ""type"": ""CreationInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";
}
