using Microsoft.Sbom.Exceptions;
using Microsoft.Sbom.Parser.Strings;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;

namespace Microsoft.Sbom.Parser;

[TestClass]
public class SbomPackageParserTests
{
    [TestMethod]
    public void ParseSbomPackagesTest()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();
        var count = 0;

        foreach (var package in parser.GetPackages(stream))
        {
            count++;
            Assert.IsNotNull(package);
        }

        Assert.AreEqual(3, count);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void NullStreamThrows()
    {
        new SbomPackageParser(null);
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public void StreamClosedTestReturnsNull()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomPackageStrings.GoodJsonWith3PackagesString);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();
        stream.Close();

        parser.GetPackages(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(EndOfStreamException))]
    public void StreamEmptyTestReturnsNull()
    {
        using var stream = new MemoryStream();
        stream.Read(new byte[Constants.ReadBufferSize]);
        var buffer = new byte[Constants.ReadBufferSize];

        TestParser parser = new ();

        parser.GetPackages(stream).GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingCopyrightText)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingDownloadLocation)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingVersionInfo)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingLicenseInfoFromFiles)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingSupplier)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingId)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingLicenseConcluded)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingLicenseDeclared)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingName)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageBadReferenceType)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingReferenceLocator)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageMissingPackageVerificationCode)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MissingPropertiesTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new (40);

        parser.GetPackages(stream).GetEnumerator().MoveNext();
    }

    [DataTestMethod]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalString)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalArray)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalObject)]
    [DataRow(SbomPackageStrings.PackageJsonWith1PackageAdditionalArrayNoKey)]
    [TestMethod]
    public void IgnoresAdditionalPropertiesTest(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();

        foreach (var package in parser.GetPackages(stream))
        {
            Assert.IsNotNull(package);
        }
    }

    [DataTestMethod]
    [DataRow(SbomPackageStrings.MalformedJson)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObject)]
    [DataRow(SbomFileJsonStrings.MalformedJsonEmptyObjectNoArrayEnd)]
    [TestMethod]
    [ExpectedException(typeof(ParserException))]
    public void MalformedJsonTest_Throws(string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();

        parser.GetPackages(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    public void EmptyArray_ValidJson()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJsonEmptyArray);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new ();

        parser.GetPackages(stream).GetEnumerator().MoveNext();
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void NullOrEmptyBuffer_Throws()
    {
        byte[] bytes = Encoding.UTF8.GetBytes(SbomFileJsonStrings.MalformedJson);
        using var stream = new MemoryStream(bytes);

        TestParser parser = new (0);

        parser.GetPackages(stream).GetEnumerator().MoveNext();
    }
}
