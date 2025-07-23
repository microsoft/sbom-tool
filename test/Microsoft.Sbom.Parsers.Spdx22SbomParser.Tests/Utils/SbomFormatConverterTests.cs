// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils.Tests;

[TestClass]
public class SbomFormatConverterTests
{
    [TestMethod]
    public void ToSbomPackage_HappyPath()
    {
        var spdxPackage = new SPDXPackage
        {
            Name = "name",
            SpdxId = "spdxId",
            LicenseConcluded = "licenseConcluded",
            LicenseDeclared = "licenseDeclared",
            CopyrightText = "copyright",
            Supplier = "supplier",
        };

        var sbomPackage = spdxPackage.ToSbomPackage();

        Assert.IsNotNull(sbomPackage);
        Assert.AreEqual(spdxPackage.Name, sbomPackage.PackageName);
        Assert.AreEqual(spdxPackage.SpdxId, sbomPackage.Id);
    }

    [TestMethod]
    public void ToSbomPackage_AcceptsEmptyLicenseInfo()
    {
        var spdxPackage = new SPDXPackage
        {
            Name = "name",
            SpdxId = "spdxId",
            LicenseConcluded = "licenseConcluded",
            LicenseDeclared = "licenseDeclared",
            CopyrightText = "copyright",
            Supplier = "supplier",
            FilesAnalyzed = true,
            LicenseInfoFromFiles = new List<string>(),
        };

        var sbomPackage = spdxPackage.ToSbomPackage();

        Assert.IsNotNull(sbomPackage);
    }

    [TestMethod]
    public void ToSbomChecksum_NullChecksum_ReturnsNull()
    {
        Checksum spdxChecksum = null;
        var sbomChecksum = spdxChecksum.ToSbomChecksum();
        Assert.IsNull(sbomChecksum, "ToSbomChecksum should return null when the input checksum is null.");
    }

    [TestMethod]
    public void ToPurl_EmptyExternalReferences_ReturnsNull()
    {
        var emptyExternalReferences = new List<ExternalReference>();
        var result = emptyExternalReferences.ToPurl();
        Assert.IsNull(result, "ToPurl should return null when external references list is empty.");
    }

    [TestMethod]
    public void ToPurl_NullExternalReferences_ReturnsNull()
    {
        IList<ExternalReference> nullExternalReferences = null;
        var result = nullExternalReferences.ToPurl();
        Assert.IsNull(result, "ToPurl should return null when external references list is null.");
    }

    [TestMethod]
    public void ToPurl_NoPackageManagerReferences_ReturnsNull()
    {
        var externalReferences = new List<ExternalReference>
        {
            new ExternalReference
            {
                ReferenceCategory = "SECURITY",
                Type = "cpe23Type",
                Locator = "cpe:2.3:a:antlr4_runtime_standard:antlr4_runtime_standard_.net:4.13.1:*:*:*:*:*:*:*"
            },
            new ExternalReference
            {
                ReferenceCategory = "OTHER",
                Type = "website",
                Locator = "https://example.com"
            }
        };

        var result = externalReferences.ToPurl();
        Assert.IsNull(result, "ToPurl should return null when no PACKAGE-MANAGER references exist.");
    }

    [TestMethod]
    public void ToPurl_WithPackageManagerReference_ReturnsCorrectPurl()
    {
        var externalReferences = new List<ExternalReference>
        {
            new ExternalReference
            {
                ReferenceCategory = "SECURITY",
                Type = "cpe23Type",
                Locator = "cpe:2.3:a:antlr4_runtime_standard:antlr4_runtime_standard_.net:4.13.1:*:*:*:*:*:*:*"
            },
            new ExternalReference
            {
                ReferenceCategory = "PACKAGE-MANAGER",
                Type = "purl",
                Locator = "pkg:nuget/Antlr4.Runtime.Standard@4.13.1"
            }
        };

        var result = externalReferences.ToPurl();
        Assert.AreEqual("pkg:nuget/Antlr4.Runtime.Standard@4.13.1", result, "ToPurl should return the package manager locator value.");
    }

    [TestMethod]
    public void ToPurl_WithUnderscoreInReferenceCategory_ReturnsCorrectPurl()
    {
        var externalReferences = new List<ExternalReference>
        {
            new ExternalReference
            {
                ReferenceCategory = "PACKAGE_MANAGER", // Using underscore format that gets converted to hyphen
                Type = "purl",
                Locator = "pkg:npm/test-package@1.0.0"
            }
        };

        var result = externalReferences.ToPurl();
        Assert.AreEqual("pkg:npm/test-package@1.0.0", result, "ToPurl should handle underscore to hyphen conversion correctly.");
    }

    [TestMethod]
    public void ToPurl_MultiplePackageManagerReferences_ReturnsFirst()
    {
        var externalReferences = new List<ExternalReference>
        {
            new ExternalReference
            {
                ReferenceCategory = "PACKAGE-MANAGER",
                Type = "purl",
                Locator = "pkg:nuget/FirstPackage@1.0.0"
            },
            new ExternalReference
            {
                ReferenceCategory = "PACKAGE-MANAGER",
                Type = "purl",
                Locator = "pkg:nuget/SecondPackage@2.0.0"
            }
        };

        var result = externalReferences.ToPurl();
        Assert.AreEqual("pkg:nuget/FirstPackage@1.0.0", result, "ToPurl should return the first PACKAGE-MANAGER reference when multiple exist.");
    }

    [TestMethod]
    public void ToPurl_PackageManagerReferenceWithNullLocator_ReturnsNull()
    {
        var externalReferences = new List<ExternalReference>
        {
            new ExternalReference
            {
                ReferenceCategory = "PACKAGE-MANAGER",
                Type = "purl",
                Locator = null
            }
        };

        var result = externalReferences.ToPurl();
        Assert.IsNull(result, "ToPurl should return null when package manager reference has null locator.");
    }
}
