// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomExternalMapJsonStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string ExternalMapJsonString =
    @"
    {
        ""externalSpdxId"": ""sample-namespace"",
        ""creationInfo"": ""_:creationinfo"",
        ""spdxId"": ""DocumentRef-sample-external-doc-sha1Value"",
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
