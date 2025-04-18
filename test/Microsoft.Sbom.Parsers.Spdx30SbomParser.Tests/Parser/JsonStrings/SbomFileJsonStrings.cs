// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.JsonStrings;

public static class SbomFileJsonStrings
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string FileWithLicensesAndHashes =
    @"[
          {
            ""name"": ""./sample/path"",
            ""software_copyrightText"": ""sampleCopyright"",
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-File-.-sample-path-sha1Value"",
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
            ""name"": ""sampleLicense1"",
            ""spdxId"": ""SPDXRef-AnyLicenseInfo-3BA3FA6D3D66FE2BA75992BB0850D080F1223256368A76C77BEF8E0F6AC71896"",
            ""type"": ""AnyLicenseInfo""
          },
          {
            ""from"": ""SPDXRef-File-.-sample-path-sha1Value"",
            ""relationshipType"": ""HAS_CONCLUDED_LICENSE"",
            ""to"": [
              ""SPDXRef-AnyLicenseInfo-3BA3FA6D3D66FE2BA75992BB0850D080F1223256368A76C77BEF8E0F6AC71896""
            ],
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-Relationship-409BEAA4D9456378E2E96E4EBC047C6477A1FEFEFE37943E61DFBEC103247718"",
            ""type"": ""Relationship""
          },
          {
            ""from"": ""SPDXRef-File-.-sample-path-sha1Value"",
            ""relationshipType"": ""HAS_DECLARED_LICENSE"",
            ""to"": [
              ""SPDXRef-AnyLicenseInfo-3BA3FA6D3D66FE2BA75992BB0850D080F1223256368A76C77BEF8E0F6AC71896""
            ],
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-Relationship-446FA437DDD74F961FED13C826EB9E6139B95162BFB071AC6002038C21C850D1"",
            ""type"": ""Relationship""
          }
        ]";
}
