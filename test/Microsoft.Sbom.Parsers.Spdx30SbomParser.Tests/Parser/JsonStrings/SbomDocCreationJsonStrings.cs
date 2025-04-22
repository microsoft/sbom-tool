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
            ""name"": ""Organization: the-package-supplier"",
            ""spdxId"": ""SPDXRef-Organization-D914F48404CB6C27373666F70709BABF08C6603E1303B97758A20190A050CE16"",
            ""type"": ""Organization""
        },
        {
            ""creationInfo"": ""_:creationinfo"",
            ""name"": ""Tool: Microsoft.SBOMTool-.*"",
            ""spdxId"": ""SPDXRef-Tool-.*"",
            ""type"": ""Tool""
        },
        {
            ""@id"": ""_:creationinfo"",
            ""created"": "".*"",
            ""createdBy"": [
                ""SPDXRef-Organization-D914F48404CB6C27373666F70709BABF08C6603E1303B97758A20190A050CE16""
            ],
            ""createdUsing"": [
                ""SPDXRef-Tool-.*""
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
            ""namespaceMap"":
            {
            ""sbom"":""http://sbom.microsoft/sbom-package-name/sbom-package-version/some-custom-value-here""
            },
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
            ""spdxId"": ""SPDXRef-Relationship-5706D1933D610748E76F18A51E1DA89F7C80399E8526E31EEF5E65658E772003"",
            ""type"": ""Relationship""
        }
    ]";
}
