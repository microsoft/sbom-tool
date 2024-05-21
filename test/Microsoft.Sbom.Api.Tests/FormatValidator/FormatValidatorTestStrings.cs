// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Tests.FormatValidator;

internal readonly struct FormatValidatorTestStrings
{
    // Means a legal 2.x SPDX with required SPDX properties, packages, and relationships.
    // Files may be present but will be ignored.
    public const string JsonSuitableForRedaction = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""externalDocumentRefs"":[],
                ""spdxVersion"": ""SPDX-2.2"",
                ""dataLicense"": ""CC0-1.0"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""name"": ""sbom-tool 1.0.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingSpdxVersion = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""externalDocumentRefs"":[],
                ""dataLicense"": ""CC0-1.0"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""name"": ""sbom-tool 1.0.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingDocumentNamespace = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""externalDocumentRefs"":[],
                ""dataLicense"": ""CC0-1.0"",
                ""spdxVersion"": ""SPDX-2.2"",
                ""name"": ""sbom-tool 1.0.0"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingSpdxDataLicense = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""externalDocumentRefs"":[],
                ""spdxVersion"": ""SPDX-2.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""name"": ""sbom-tool 1.0.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingSpdxName = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""externalDocumentRefs"":[],
                ""spdxVersion"": ""SPDX-2.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""dataLicense"": ""CC0-1.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingSpdxPackages = /*lang=json,strict*/ @"{
                ""files"":[],
                ""relationships"":[],
                ""name"": ""sbom-tool 1.0.0"",
                ""externalDocumentRefs"":[],
                ""spdxVersion"": ""SPDX-2.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""dataLicense"": ""CC0-1.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingSpdxRelationships = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""name"": ""sbom-tool 1.0.0"",
                ""externalDocumentRefs"":[],
                ""spdxVersion"": ""SPDX-2.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""dataLicense"": ""CC0-1.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonMissingSpdxCreationInfo = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""externalDocumentRefs"":[],
                ""name"": ""sbom-tool 1.0.0"",
                ""spdxVersion"": ""SPDX-2.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""dataLicense"": ""CC0-1.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string JsonUnsupportedSpdxVersion = /*lang=json,strict*/ @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""name"": ""sbom-tool 1.0.0"",
                ""externalDocumentRefs"":[],
                ""spdxVersion"": ""SPDX-3.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""dataLicense"": ""CC0-1.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";

    public const string MalformedJson = @"{
                ""files"":[],
                ""packages"":[],
                ""relationships"":[],
                ""name"": ""sbom-tool 1.0.0"",
                ""externalDocumentRefs"":[,
                ""spdxVersion"": ""SPDX-3.2"",
                ""SPDXID"": ""SPDXRef-DOCUMENT"",
                ""dataLicense"": ""CC0-1.0"",
                ""documentNamespace"": ""https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g"",
                ""creationInfo"": {
                ""created"": ""2024-05-08T15:58:25Z"",
                ""creators"": [
                    ""Organization: Test"",
                    ""Tool: Microsoft.SBOMTool-2.2.5""
                    ]},
                ""documentDescribes"": [
                    ""SPDXRef-RootPackage""
                    ]}";
}
