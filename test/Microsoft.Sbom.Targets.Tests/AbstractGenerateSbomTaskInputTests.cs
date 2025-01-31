// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
#if NET472
using System.Linq;
#endif
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public abstract class AbstractGenerateSbomTaskInputTests
{
    internal abstract string SbomSpecification { get; }

    internal static readonly string CurrentDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
    internal static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    internal static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temporary");
    internal static readonly string BuildComponentPath = Path.Combine(CurrentDirectory, "..", "..", "..");
    internal static readonly string ExternalDocumentListFile = Path.GetRandomFileName();
    internal static string SbomToolPath = Path.Combine(Directory.GetCurrentDirectory(), "sbom-tool");
    internal const string PackageSupplier = "Test-Microsoft";
    internal const string PackageName = "CoseSignTool";
    internal const string PackageVersion = "0.0.1";
    internal const string NamespaceBaseUri = "https://base0.uri";
    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;
    private List<BuildMessageEventArgs> messages;

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        this.buildEngine = new Mock<IBuildEngine>();
        this.errors = new List<BuildErrorEventArgs>();
        this.messages = new List<BuildMessageEventArgs>();
        this.buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));
        this.buildEngine.Setup(x => x.LogMessageEvent(It.IsAny<BuildMessageEventArgs>())).Callback<BuildMessageEventArgs>(msg => messages.Add(msg));
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
    /// Test for ensuring the GenerateSbom fails for null or empty inputs for
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
        string namespaceBaseUri,
        string sbomToolPath)
    {
        // Arrange.
        var task = new GenerateSbom
        {
            BuildDropPath = buildDropPath,
            PackageSupplier = packageSupplier,
            PackageName = packageName,
            PackageVersion = packageVersion,
            NamespaceBaseUri = namespaceBaseUri,
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
#if NET472
            SbomToolPath = sbomToolPath,
#endif
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    private static IEnumerable<object[]> GetNullRequiredParamsData()
    {
        yield return new object[] { null, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, null, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, null, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, null, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, null, SbomToolPath };
#if NET472
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, null };
#endif
    }

    private static IEnumerable<object[]> GetEmptyRequiredParamsData()
    {
        yield return new object[] { string.Empty, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, string.Empty, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, string.Empty, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, string.Empty, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, string.Empty, SbomToolPath };
#if NET472
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, string.Empty };
#endif
    }

    private static IEnumerable<object[]> GetWhiteSpace_Tabs_NewLineParamsData()
    {
        yield return new object[] { " ", PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, "\n", PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, "\t", PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, " \n \t \n \t \n    ", NamespaceBaseUri, SbomToolPath };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, "\t \t \t   ", SbomToolPath };
#if NET472
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, "\t \t \t   " };
#endif
    }

    /// <summary>
    /// Test for ensuring the GenerateSbom fails when user provides an
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
        var task = new GenerateSbom
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = namespaceBaseUri,
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
#if NET472
            SbomToolPath = SbomToolPath,
#endif
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Test for ensuring the GenerateSbom fails when user provides
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
    [DataRow("12345678-1234-1234-1234-12345\n6789ac")] // Contains newline
    [DataRow("00000000-0000-0000-0000-000000000000")] // Empty guid
    public void Sbom_Generation_Fails_For_Invalid_NamespaceUriUniquePart(string namespaceUriUniquePart)
    {
        // Arrange
        var task = new GenerateSbom
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            NamespaceUriUniquePart = namespaceUriUniquePart,
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
#if NET472
            SbomToolPath = SbomToolPath,
#endif
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Test for ensuring GenerateSbom assigns a defualt Verbosity
    /// level when null input is provided.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Null_Verbosity()
    {
        // Arrange
        // If Verbosity is null, the default value should be Information and is printed in the
        // tool's standard output.
        var pattern = new Regex("Verbosity=.*Value=Information");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbom
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            ManifestInfo = this.SbomSpecification,
            Verbosity = null,
            BuildEngine = this.buildEngine.Object,
#if NET472
            SbomToolPath = SbomToolPath,
#endif
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
#if NET472
        Assert.IsTrue(this.messages.Any(msg => pattern.IsMatch(msg.Message)));
#else
        Assert.IsTrue(pattern.IsMatch(output));
#endif
    }

    /// <summary>
    /// Test for ensuring GenerateSbom assigns a default Verbosity for
    /// unrecognized input.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Invalid_Verbosity()
    {
        // Arrange
        // If an invalid Verbosity is specified, the default value should be Information. It is also printed in the
        // tool's standard output for the MSBuild Core task.
        var pattern = new Regex("Verbosity=.*Value=Information");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbom
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = "Invalid Verbosity",
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
#if NET472
            SbomToolPath = SbomToolPath,
#endif
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
#if NET472
        Assert.IsTrue(this.messages.Any(msg => pattern.IsMatch(msg.Message)));
#else
        Assert.IsTrue(pattern.IsMatch(output));
#endif
    }

#if !NET472
    /// <summary>
    /// Test to ensure GenerateSbom correctly parses and provides each EventLevel verbosity
    /// values to the SBOM API.
    /// </summary>
    [TestMethod]
    [DataRow("FATAL", "Fatal", false)]
    [DataRow("information", "Information", true)]
    [DataRow("vErBose", "Verbose", true)]
    [DataRow("Warning", "Warning", false)]
    [DataRow("eRRor", "Error", false)]
    [DataRow("DeBug", "Verbose", true)]
    public void Sbom_Generation_Assigns_Correct_Verbosity_IgnoreCase(string inputVerbosity, string mappedVerbosity, bool messageShouldBeLogged)
    {
        if (!messageShouldBeLogged)
        {
            Assert.Inconclusive("Cases where the input Verbosity is more restrictive than `Information` are failing due to this issue: https://github.com/microsoft/sbom-tool/issues/616");
        }

        // Arrange
        var pattern = new Regex($"Verbosity=.*Value={mappedVerbosity}");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbom
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = inputVerbosity,
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result, $"result: {result} is not set to true");
        Assert.AreEqual(messageShouldBeLogged, pattern.IsMatch(output));
    }
#else
    /// <summary>
    /// Test to ensure GenerateSbom correctly parses and provides each verbosity option
    /// to the SBOM CLI.
    /// </summary>
    [TestMethod]
    [DataRow("FATAL", "Fatal", false)]
    [DataRow("information", "Information", true)]
    [DataRow("vErBose", "Verbose", true)]
    [DataRow("Warning", "Warning", false)]
    [DataRow("eRRor", "Error", false)]
    [DataRow("DeBug", "Debug", true)]
    public void Sbom_Generation_Assigns_Correct_Verbosity_IgnoreCase(string inputVerbosity, string mappedVerbosity, bool messageShouldBeLogged)
    {
        // Arrange
        var pattern = new Regex($"Verbosity=.*Value={mappedVerbosity}");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbom
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = inputVerbosity,
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
            SbomToolPath = SbomToolPath,
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result, $"result: {result} is not set to true");
        Assert.AreEqual(messageShouldBeLogged, this.messages.Any(msg => pattern.IsMatch(msg.Message)));
    }
#endif
}
