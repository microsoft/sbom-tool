// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomFullDocWithMetadataJsonStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomWithValidMetadataJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""name"": ""CC0-1.0"",
                ""spdxId"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""type"": ""AnyLicenseInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
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
    public const string SbomWithSpdxDocumentMissingNameJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""name"": ""CC0-1.0"",
                ""spdxId"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""type"": ""AnyLicenseInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomWithMultipleSpdxDocumentsJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""name"": ""CC0-1.0"",
                ""spdxId"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""type"": ""AnyLicenseInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc1-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc2-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-A93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomWithMissingCreationInfoJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""CC0-1.0"",
                ""spdxId"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""type"": ""AnyLicenseInfo""
            },
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
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
    public const string SbomWithMissingValidCreationInfoJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
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
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""CC0-1.0"",
                ""spdxId"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""type"": ""AnyLicenseInfo""
            },
            {
                ""@id"": ""invalidId"",
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
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
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
    public const string SbomWithInvalidContextJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld"",
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""the-package-namethe-package-version"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }
        ]
    }
    ";

    public const string MalformedJsonEmptyObject =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
        ],
        ""@graph"":
        {
        }";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string MalformedJsonEmptyArray =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
        ],
        ""@graph"":
        [
            {
                ""creationInfo"": ""_:creationinfo"",
                ""namespaceMap"": {
                    ""sbom"": ""https://sbom.microsoft/1:EUb7DmXV0UyaZH1sttfV8A:n5KOcNVrWkGNryWx2sCN2A/13824:29192253/5qzhWC8k2k2wzStO28rMVQ""
                },
                ""rootElement"": [
                    ""root-element-example""
                ],
                ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
                ""profileConformance"": [
                    ""software"",
                    ""core""
                ],
                ""name"": ""spdx-doc-name"",
                ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
                ""type"": ""SpdxDocument""
            }   
    }";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]

    public const string JsonEmptyArray =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
        ],
        ""@graph"": [
        ]
    }";
}
