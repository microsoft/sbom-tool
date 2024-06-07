// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public abstract class AbstractGenerateSBomTaskInputTests
{
    internal abstract SbomSpecification SbomSpecification { get; }

    internal static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    internal static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    internal static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temporary");
    internal static readonly string BuildComponentPath = Path.Combine(CurrentDirectory, "..", "..", "..");
    internal static readonly string ExternalDocumentListFile = Path.GetRandomFileName();
    internal const string PackageSupplier = "Test-Microsoft";
    internal const string PackageName = "CoseSignTool";
    internal const string PackageVersion = "0.0.1";
    internal const string NamespaceBaseUri = "https://base0.uri";

    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        this.buildEngine = new Mock<IBuildEngine>();
        this.errors = new List<BuildErrorEventArgs>();
        this.buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));
    }

    [TestCleanup]
    public void Cleanup() {
        // Clean up the manifest directory
        if (Directory.Exists(DefaultManifestDirectory))
        {
            Directory.Delete(DefaultManifestDirectory, true);
        }

        // Clean up the manifest directory
        if (Directory.Exists(TemporaryDirectory))
        {
            Directory.Delete(TemporaryDirectory, true);
        }
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails for null or empty inputs for
    /// required params, which includes BuildDropPath, PackageSupplier, PackageName,
    /// PackageVersion, and NamespaceBaseUri.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(GetNullRequiredParamsData), DynamicDataSourceType.Method)]
    [DynamicData(nameof(GetEmptyRequiredParamsData), DynamicDataSourceType.Method)]
    [DynamicData(nameof(GetWhiteSpace_Tabs_NewLineParamsData), DynamicDataSourceType.Method)]
    public void Sbom_Fails_With_Null_Empty_And_WhiteSpace_Required_Params(
        string buildDropPath,
        string packageSupplier,
        string packageName,
        string packageVersion,
        string namespaceBaseUri)
    {
        // Arrange.
        var task = new GenerateSbomTask
        {
            BuildDropPath = buildDropPath,
            PackageSupplier = packageSupplier,
            PackageName = packageName,
            PackageVersion = packageVersion,
            NamespaceBaseUri = namespaceBaseUri,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    private static IEnumerable<object[]> GetNullRequiredParamsData()
    {
        yield return new object[] { null, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, null, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, null, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, null, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, null };
    }

    private static IEnumerable<object[]> GetEmptyRequiredParamsData()
    {
        yield return new object[] { string.Empty, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, string.Empty, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, string.Empty, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, string.Empty, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, string.Empty };
    }

    private static IEnumerable<object[]> GetWhiteSpace_Tabs_NewLineParamsData()
    {
        yield return new object[] { " ", PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, "\n", PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, "\t", PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, " \n \t \n \t \n    ", NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, "\t \t \t   " };
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails when user provides an
    /// invalid URI format.
    /// </summary>
    [TestMethod]
    [DataRow("incorrectly_formatted_uri.com")] // Missing protocol
    [DataRow("http://invalid.com:70000")] // Invalid port
    [DataRow("http://inv\nalid.com")] // Contains new line character
    [DataRow("http://invalid.com/path with spaces")] // Contains spaces
    [DataRow("http:invalid.com")] // Missing // after protocol
    [DataRow("http://")] // Missing domain
    public void Sbom_Fails_With_Invalid_NamespaceBaseUri(string namespaceBaseUri)
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = namespaceBaseUri,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails when user provides
    /// an invalid GUID for NamespaceUriUniquePart.
    /// </summary>
    [TestMethod]
    [DataRow("-1")] // starts with hyphen
    [DataRow("1234567890")] // Too less digits
    [DataRow("12345678-1234-1234-1234-123456789abcd")] // Too many digits
    [DataRow("12345678-1234-1234-1234-123456789abg")] // invalid character g
    [DataRow("12345678-1234-1234-1234-123456789ab!")] // invalid character !
    [DataRow("12345678-1234-1234-1234-123456789ab")] // Too less digits
    [DataRow("12345678-1234-1234-1234-123456789ac-")] // Ends with a hyphen
    public void Sbom_Generation_Fails_For_Invalid_NamespaceUriUniquePart(string namespaceUriUniquePart)
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            NamespaceUriUniquePart = namespaceUriUniquePart,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails when relative paths are
    /// provided for all path arguments, which includes BuildDroppath, BuildComponentPath,
    /// ManifestDirPath, and ExternalDocumentListFile
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(GetUnrootedPathTestData), DynamicDataSourceType.Method)]
    public void Sbom_Fails_With_Unrooted_Paths(
        string buildDropPath,
        string buildComponentPath,
        string manifestDirPath,
        string externalDocumentListFile)
    {
        // Arrange.
        var task = new GenerateSbomTask
        {
            BuildDropPath = buildDropPath,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildComponentPath = buildComponentPath,
            ManifestDirPath = manifestDirPath,
            ExternalDocumentListFile = externalDocumentListFile,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    private static IEnumerable<object[]> GetUnrootedPathTestData()
    {
        yield return new object[] { Path.Combine("..", ".."), BuildComponentPath, DefaultManifestDirectory, ExternalDocumentListFile };
        yield return new object[] { CurrentDirectory, Path.Combine("..", ".."), DefaultManifestDirectory, ExternalDocumentListFile };
        yield return new object[] { CurrentDirectory, BuildComponentPath, Path.Combine("..", ".."), ExternalDocumentListFile };
        yield return new object[] { CurrentDirectory, BuildComponentPath, DefaultManifestDirectory, Path.Combine("..", "..") };
    }

    /// <summary>
    /// Test for ensuring GenerateSbomTask assigns a defualt Verbosity
    /// level when null input is provided.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Null_Verbosity()
    {
        // Arrange
        // If Verbosity is null, the default value should be Verbose and is printed in the
        // tool's standard output.
        var pattern = new Regex("Verbosity=.*Value=Verbose");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            ManifestInfo = this.SbomSpecification.ToString(),
            Verbosity = null,
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(pattern.IsMatch(output));
    }

    /// <summary>
    /// Test for ensuring GenerateSbomTask assigns a default Verbosity for
    /// unrecognized input.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Invalid_Verbosity()
    {
        // Arrange
        // If an invalid Verbosity is specified, the default value should be Verbose and is printed in the
        // tool's standard output.
        var pattern = new Regex("Verbosity=.*Value=Verbose");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = "Invalid Verbosity",
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(pattern.IsMatch(output));
    }

    /// <summary>
    /// Test to ensure GenerateSbomTask correctly parses and provides each EventLevel verbosity
    /// values to the SBOM API.
    /// </summary>
    [TestMethod]
    [DataRow("CRITICAL", "Fatal")]
    [DataRow("informational", "Information")]
    [DataRow("LoGAlwAys", "Verbose")]
    [DataRow("Warning", "Warning")]
    [DataRow("eRRor", "Error")]
    [DataRow("verBOSE", "Verbose")]
    public void Sbom_Generation_Assigns_Correct_Verbosity_IgnoreCase(string inputVerbosity, string mappedVerbosity)
    {
        // Arrange
        var pattern = new Regex($"Verbosity=.*Value={mappedVerbosity}");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = inputVerbosity,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(pattern.IsMatch(output));
    }
}
