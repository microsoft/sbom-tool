// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomExternalMapJsonStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string ExternalMapJsonString =
    @"
    {
        ""externalSpdxId"": ""DocumentRef-sample-external-doc-sha1Value"",
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""SPDXRef-ExternalMap-2AB84930C880E9632BC8FCFBC0BA22D66E2912252D3457ACB89A9DDE4745E2D0"",
        ""verifiedUsing"": [
        {
            ""algorithm"": ""sha1"",
            ""hashValue"": ""sha1value"",
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-PackageVerificationCode-B1565820A5CDAC40E0520D23F9D0B1497F240DDC51D72EAC6423D97D952D444F"",
            ""type"": ""PackageVerificationCode""
        }
        ],
        ""type"": ""ExternalMap""
    }";
}
