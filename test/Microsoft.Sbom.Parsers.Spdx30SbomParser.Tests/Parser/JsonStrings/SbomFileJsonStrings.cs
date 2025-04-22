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
            ""creationInfo"": ""_:creationinfo"",
            ""name"": ""sampleLicense2"",
            ""spdxId"": ""SPDXRef-AnyLicenseInfo-D6DF0CBEE7E2F48211D701973C9B5EE5440D18CA45E5BD82C15C9336A1FF79A4"",
            ""type"": ""AnyLicenseInfo""
          },
          {
            ""from"": ""SPDXRef-File-.-sample-path-sha1Value"",
            ""relationshipType"": ""HAS_DECLARED_LICENSE"",
            ""to"": [
              ""SPDXRef-AnyLicenseInfo-D6DF0CBEE7E2F48211D701973C9B5EE5440D18CA45E5BD82C15C9336A1FF79A4""
            ],
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-Relationship-446FA437DDD74F961FED13C826EB9E6139B95162BFB071AC6002038C21C850D1"",
            ""type"": ""Relationship""
          }
    ]";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "JSON002:Probable JSON string detected", Justification = "Need to use JSON string")]
    public const string FileWithNoDeclaredLicense =
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
            ""spdxId"": ""SPDXRef-Relationship-2A69D50DCB6D763C5C4FFCE6A4F6C3166DD8F6DB3F77BDD4B6129C0B33F238DA"",
            ""type"": ""Relationship""
          },
          {
            ""creationInfo"": ""_:creationinfo"",
            ""name"": ""NOASSERTION"",
            ""spdxId"": ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969"",
            ""type"": ""Element""
          },
          {
            ""from"": ""SPDXRef-File-.-sample-path-sha1Value"",
            ""relationshipType"": ""HAS_DECLARED_LICENSE"",
            ""to"": [
              ""SPDXRef-Element-8560FC6692684D8DF52223FF78E30B9630A1CF5A6FA371AAE24FCA896AE20969""
            ],
            ""creationInfo"": ""_:creationinfo"",
            ""spdxId"": ""SPDXRef-Relationship-222E099165617B282F2B424519FC133796AA0189D0238FD121CCF3B0340D4301"",
            ""type"": ""Relationship""
          }
    ]";
}
