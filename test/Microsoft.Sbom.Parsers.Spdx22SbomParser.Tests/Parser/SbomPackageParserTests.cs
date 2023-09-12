// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JsonStreaming;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomPackageParserTests
{
    [TestMethod]
    public async Task ParseSbomPackagesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);

        Assert.AreEqual(3, parser.PackageCount);
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public async Task StreamClosedTestReturnsNull()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
        stream.Close();
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public async Task StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [DataTestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingDownloadLocation)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingVersionInfo)]
    public async Task MissingPropertiesTest_DoesNotThrow(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [DataTestMethod]
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
    [ExpectedException(typeof(ParserException))]
    public async Task MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [DataTestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalString)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalArray)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalObject)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalArrayNoKey)]
    public async Task IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [DataTestMethod]
    [DataRow(SbomPackageStrings.MalformedJson)]
    [DataRow(SbomPackageStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomPackageStrings.MalformedJsonEmptyObjectNoArrayEnd)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public async Task MalformedJsonTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [TestMethod]
    public async Task EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream);

        await parser.ParseAsync(CancellationToken.None);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public async Task NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        var parser = new TestSPDXParser(stream, bufferSize: 0);

        await parser.ParseAsync(CancellationToken.None);
    }
}
