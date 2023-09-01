// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser.Strings;

internal struct SbomPackageStrings
{
    public SbomPackageStrings()
    {
    }

    public const string PackageJsonWith1PackageAdditionalString = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""other"": ""tt"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    }]}";

    public const string PackageJsonWith1PackageAdditionalArray = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""additionalProperty"": [
        {""childAddtionalProperty"": ""Additional property value"" }],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    }]}";

    public const string PackageJsonWith1PackageAdditionalArrayNoKey = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""additionalProperty"": [""Additional value 1"", ""Additional value 2""],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    }]}";

    public const string PackageJsonWith1PackageAdditionalObject = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""additionalProperty"": {
        ""childAddtionalProperty"": ""Additional property value""
      },
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    }]}";

    public const string MalformedJsonEmptyObject = @"{
      ""packages"":{}}";

    public const string MalformedJsonEmptyObjectNoArrayEnd = @"{
      ""packages"":[}";

    public const string MalformedJson = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0,
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    }]}";

    public const string PackageJsonWith1PackageFilesAnalyzedTrueAndMissingLicenseInfoFromFiles = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""other"": ""tt"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    }]}";

    public const string PackageJsonWith1PackageMissingPackageVerificationCode = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": """"
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingReferenceLocator = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ],
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
        }
      ],
    }]}";

    public const string PackageJsonWith1PackageBadReferenceType = @"{
       ""packages"": [{
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ],
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""testss"",
          ""referenceLocator"": ""pkg:nuget/System.Runtime.InteropServices.WindowsRuntime%404.3.0""
        }
      ],
    }]}";

    public const string PackageJsonWith1PackageMissingName = @"{
       ""packages"": [{
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingId = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingDownloadLocation = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingFilesAnalyzed = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingLicenseConcluded = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingLicenseInfoFromFiles = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingLicenseDeclared = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingCopyrightText = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingVersionInfo = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string PackageJsonWith1PackageMissingSupplier = @"{
       ""packages"": [{
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";

    public const string MalformedJsonEmptyArray = @"{""packages"": []}";

    public const string GoodJsonWith3PackagesString = @"{
       ""packages"": [
    {
      ""name"": ""pest"",
      ""SPDXID"": ""SPDXRef-Package-1C4595D6D70121622649BB913859B18A3C0A2D49EC7D36279777025C4AC92303"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1.0.0"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""pkg:nuget/pest%401.0.0""
        }
      ],
      ""supplier"": ""Organization: testa""
    },
    {
      ""name"": ""Azure Pipelines Hosted Image win22"",
      ""SPDXID"": ""SPDXRef-Package-8A7096C32BB7E49E0D8FEAB886ECEDDBF108DCBA505DD9E8AAB73C294F903EB2"",
      ""downloadLocation"": ""NOASSERTION"",
      ""filesAnalyzed"": false,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""20220905.1"",
      ""externalRefs"": [
        {
          ""referenceCategory"": ""PACKAGE_MANAGER"",
          ""referenceType"": ""purl"",
          ""referenceLocator"": ""https://github.com/actions/virtual-environments""
        }
      ],
      ""supplier"": ""Organization: Microsoft/GitHub""
    },
    {
      ""name"": ""Testing cross platform signing"",
      ""SPDXID"": ""SPDXRef-RootPackage"",
      ""downloadLocation"": ""NOASSERTION"",
      ""packageVerificationCode"": {
        ""packageVerificationCodeValue"": ""a2f8875f69c1b3814120e98bd3c0864e3c586a24""
      },
      ""filesAnalyzed"": true,
      ""licenseConcluded"": ""NOASSERTION"",
      ""licenseInfoFromFiles"": [
        ""NOASSERTION""
      ],
      ""licenseDeclared"": ""NOASSERTION"",
      ""copyrightText"": ""NOASSERTION"",
      ""versionInfo"": ""1208"",
      ""supplier"": ""Organization: Microsoft"",
      ""hasFiles"": [
        ""SPDXRef-File--package-services-metadata-core-properties-16e5bdb646ef44f485b1227d6d005f14.psmdcp-81EC7E121D7F03CDE59C8A4570A7D75C7EBB063A"",
        ""SPDXRef-File--packages.config-69B7910C6FC95DB019934AA3BE0CDFDC3F3F2D8E"",
        ""SPDXRef-File--pest.nuspec-A2EBA85861EAFD340496A9A7948D193284A19408"",
        ""SPDXRef-File---rels-.rels-2DBE1B6566BFF9F17C259FB7D8B21231D4F11857"",
        ""SPDXRef-File---Content-Types-.xml-EB0036B6C11A1AF694FA8ABACA0A4C43584225DE""
      ]
    }]}";
}
