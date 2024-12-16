// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomDocCreationJsonStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string DocCreationJsonString =
    @"[
        {
            ""creationInfo"": ""_:creationinfo"",
            ""name"": ""the-package-supplier"",
            ""spdxId"": ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81"",
            ""type"": ""Organization""
        },
        {
            ""creationInfo"": ""_:creationinfo"",
            ""name"": ""Microsoft.SBOMTool-.*"",
            ""spdxId"": ""SPDXRef-Tool-1B22F89585B6EBBBC634E29621D531A555FAC621C99076D91BB6CAC2D3B494BC"",
            ""type"": ""Tool""
        },
        {
            ""@id"": ""_:creationinfo"",
            ""created"": "".*"",
            ""createdBy"": [
                ""SPDXRef-Organization-4B8D792FFFFCD3AF92D53A739B6DF98DF2B1F367C2745DDC0085B30F51EBBC81""
            ],
            ""createdUsing"": [
                ""SPDXRef-Tool-1B22F89585B6EBBBC634E29621D531A555FAC621C99076D91BB6CAC2D3B494BC""
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
            ""dataLicense"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
            ""namespaceMap"": [
                {
                    ""namespace"": ""http://sbom.microsoft/sbom-package-name/sbom-package-version/some-custom-value-here"",
                    ""creationInfo"": ""_:creationinfo"",
                    ""spdxId"": ""SPDXRef-NamespaceMap-0C5D68EB49795A98E060EB263AC73F87322217857EB3057EBAC84A70F75E69BE"",
                    ""type"": ""NamespaceMap""
                }
            ],
            ""profileConformance"": [
                ""software"",
                ""core"",
                ""simpleLicensing""
            ],
            ""creationInfo"": ""_:creationinfo"",
            ""name"": ""the-package-namethe-package-version"",
            ""spdxId"": ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1"",
            ""type"": ""SpdxDocument""
        },
        {
            ""from"": ""SPDXRef-AnyLicenseInfo-6E237C55B0583CB7BBA05562316C54B0A105ABA04775017E2253237B9A64613C"",
            ""relationshipType"": ""HAS_DECLARED_LICENSE"",
            ""to"": [
                ""SPDXRef-SpdxDocument-B93EED20C16A89A887B753958D42B794DD3C6570D3C2725B56B43477B38E05A1""
            ],
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
            ""type"": ""Relationship""
        }
    ]";
}
