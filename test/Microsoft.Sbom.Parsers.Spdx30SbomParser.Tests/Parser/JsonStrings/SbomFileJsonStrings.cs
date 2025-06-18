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
            ""spdxId"": ""SPDXRef-Relationship-751F53F899981D8472EEB2EFBF87449AF91CBDAE25604D7A47F3274E61C41DA7"",
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
            ""spdxId"": ""SPDXRef-Relationship-409BEAA4D9456378E2E96E4EBC047C6477A1FEFEFE37943E61DFBEC103247718"",
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
            ""spdxId"": ""SPDXRef-Relationship-00736708C7FE91009D51BF522C9C797626D02764C64A2753D0EF405DC39A6466"",
            ""type"": ""Relationship""
          }
    ]";
}
