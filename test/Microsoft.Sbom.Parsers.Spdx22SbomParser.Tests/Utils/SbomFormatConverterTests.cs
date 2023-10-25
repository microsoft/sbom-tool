// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
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
    public void ToSbomPackage_FailsOnEmptyLicenseInfo()
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

        Assert.ThrowsException<ParserException>(spdxPackage.ToSbomPackage);
    }
}
