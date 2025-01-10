// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomFullDocWithFilesStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string SbomWithValidFileJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""software_copyrightText"": ""sampleCopyright"",
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""./sample/path"",
                ""spdxId"": ""SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967"",
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
                    ""spdxId"": ""SPDXRef-PackageVerificationCode-5D5B09F6DCB2D53A5FFFC60C4AC0D55FABDF556069D6631545F42AA6E3500F2E"",
                    ""type"": ""PackageVerificationCode""
                    }
                ],
                ""type"": ""software_File""
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
    public const string SbomFileWithMissingVerificationJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""software_copyrightText"": ""sampleCopyright"",
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""./sample/path"",
                ""spdxId"": ""SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967"",
                ""type"": ""software_File""
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
    public const string SbomFileWithMissingSHA256JsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""software_copyrightText"": ""sampleCopyright"",
                ""creationInfo"": ""_:creationinfo"",
                ""verifiedUsing"": [
                    {
                    ""algorithm"": ""sha1"",
                    ""hashValue"": ""sha1value"",
                    ""creationInfo"": ""_:creationinfo"",
                    ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
                    ""type"": ""PackageVerificationCode""
                    }
                ],
                ""name"": ""./sample/path"",
                ""spdxId"": ""SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967"",
                ""type"": ""software_File""
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
    public const string SbomFileWithMissingNameJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""software_copyrightText"": ""sampleCopyright"",
                ""creationInfo"": ""_:creationinfo"",
                ""spdxId"": ""SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967"",
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
                    ""spdxId"": ""SPDXRef-PackageVerificationCode-5D5B09F6DCB2D53A5FFFC60C4AC0D55FABDF556069D6631545F42AA6E3500F2E"",
                    ""type"": ""PackageVerificationCode""
                    }
                ],
                ""type"": ""software_File""
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
    public const string SbomFileWithMissingSpdxIdJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
          ],
        ""@graph"": [
            {
                ""software_copyrightText"": ""sampleCopyright"",
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""./sample/path"",
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
                    ""spdxId"": ""SPDXRef-PackageVerificationCode-5D5B09F6DCB2D53A5FFFC60C4AC0D55FABDF556069D6631545F42AA6E3500F2E"",
                    ""type"": ""PackageVerificationCode""
                    }
                ],
                ""type"": ""software_File""
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
    public const string SbomFileWithAdditionalPropertiesJsonString =
    @"
    {
        ""@context"": [
            ""https://spdx.org/rdf/3.0.1/spdx-context.jsonld""
         ],
        ""@graph"": [
            {
                ""software_copyrightText"": ""sampleCopyright"",
                ""creationInfo"": ""_:creationinfo"",
                ""name"": ""./sample/path"",
                ""spdxId"": ""SPDXRef-software_File-B4A9F99A3A03B9273AE34753D96564CB4F2B0FAD885BBD36B0DD619E9E8AC967"",
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
                    ""spdxId"": ""SPDXRef-PackageVerificationCode-5D5B09F6DCB2D53A5FFFC60C4AC0D55FABDF556069D6631545F42AA6E3500F2E"",
                    ""type"": ""PackageVerificationCode""
                }
                ],
                ""type"": ""software_File"",
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
}
