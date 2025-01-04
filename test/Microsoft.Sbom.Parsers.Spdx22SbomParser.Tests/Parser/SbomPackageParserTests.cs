// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomPackageParserTests : SbomParserTestsBase
{
    [TestMethod]
    public void ParseSbomPackagesTest()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);

        Assert.AreEqual(3, result.PackagesCount);
    }

    [TestMethod]
    public void StreamClosedTestReturnsNull()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        Assert.ThrowsException<ObjectDisposedException>(() => this.Parse(parser, stream, close: true));
    }

    [TestMethod]
    public void StreamEmptyTestThrowsException()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        Assert.ThrowsException<EndOfStreamException>(() => new SPDXParser(stream));
    }

    [TestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingDownloadLocation)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingVersionInfo)]
    public void MissingPropertiesTest_DoesNotThrow(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);
    }

    [TestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingCopyrightText)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingLicenseInfoFromFiles)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingSupplier)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingId)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingLicenseConcluded)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingLicenseDeclared)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingName)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageBadReferenceType)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingReferenceLocator)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingPackageVerificationCode)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageFilesAnalyzedTrueAndMissingLicenseInfoFromFiles)]
    public void MissingPropertiesTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalString)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalArray)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalObject)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalArrayNoKey)]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);
    }

    [DataRow(SbomPackageStrings.MalformedJson)]
    [DataRow(SbomPackageStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomPackageStrings.MalformedJsonEmptyObjectNoArrayEnd)]
    [TestMethod]
    public void MalformedJsonTest_Throws(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        Assert.ThrowsException<ParserException>(() => this.Parse(parser));
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new SPDXParser(stream);

        var result = this.Parse(parser);
    }

    [TestMethod]
    public void NullOrEmptyBuffer_Throws()
    {
        var bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        Assert.ThrowsException<ArgumentException>(() => new SPDXParser(stream, bufferSize: 0));
    }
}
