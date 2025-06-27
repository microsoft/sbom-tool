// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Microsoft.Build.Framework;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public abstract class AbstractGenerateSbomTaskInputTests
{
    internal virtual string SbomSpecification { get; }

    internal static string TestBuildDropPath;
    internal static string DefaultManifestDirectory;
    internal static string TemporaryDirectory;
    internal static string ExternalDocumentListFile;
    internal static string SbomToolPath;

    internal const string PackageSupplier = "Test-Microsoft";
    internal const string PackageName = "CoseSignTool";
    internal const string PackageVersion = "0.0.1";
    internal const string NamespaceBaseUri = "https://base0.uri";

#if NET472
    private const string TargetFramework = "net472";
#else
    private const string TargetFramework = "net80";
#endif

    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;
    private List<BuildMessageEventArgs> messages;
    private List<BuildWarningEventArgs> warnings;

    protected static void ClassSetup(string testDirectoryName)
    {
        var executingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        TestBuildDropPath = Path.GetFullPath(Path.Combine(executingDirectory, "..", $"{testDirectoryName}_{TargetFramework}"));
        DefaultManifestDirectory = Path.Combine(TestBuildDropPath, "_manifest");
        TemporaryDirectory = Path.Combine(TestBuildDropPath, "_temp");
        ExternalDocumentListFile = Path.GetRandomFileName();
        SbomToolPath = Path.Combine(TestBuildDropPath, "sbom-tool");
        Xcopy(executingDirectory, TestBuildDropPath);
    }

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        this.buildEngine = new Mock<IBuildEngine>();
        this.errors = new List<BuildErrorEventArgs>();
        this.messages = new List<BuildMessageEventArgs>();
        this.warnings = new List<BuildWarningEventArgs>();
        this.buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));
        this.buildEngine.Setup(x => x.LogMessageEvent(It.IsAny<BuildMessageEventArgs>())).Callback<BuildMessageEventArgs>(msg => messages.Add(msg));
        this.buildEngine.Setup(x => x.LogWarningEvent(It.IsAny<BuildWarningEventArgs>())).Callback<BuildWarningEventArgs>(w => warnings.Add(w));
    }

    [TestCleanup]
    public void Cleanup()
    {
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

    protected static void ClassTearDown()
    {
        // Clean up the TestBuildDropPath directory
        if (TestBuildDropPath is not null)
        {
            if (Directory.Exists(TestBuildDropPath))
            {
                Directory.Delete(TestBuildDropPath, true);
            }
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
        yield return new object[] { TestBuildDropPath, null, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, null, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, null, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, PackageVersion, null, SbomToolPath };
#if NET472
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, null };
#endif
    }

    private static IEnumerable<object[]> GetEmptyRequiredParamsData()
    {
        yield return new object[] { string.Empty, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, string.Empty, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, string.Empty, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, string.Empty, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, PackageVersion, string.Empty, SbomToolPath };
#if NET472
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, string.Empty };
#endif
    }

    private static IEnumerable<object[]> GetWhiteSpace_Tabs_NewLineParamsData()
    {
        yield return new object[] { " ", PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, "\n", PackageName, PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, "\t", PackageVersion, NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, " \n \t \n \t \n    ", NamespaceBaseUri, SbomToolPath };
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, PackageVersion, "\t \t \t   ", SbomToolPath };
#if NET472
        yield return new object[] { TestBuildDropPath, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri, "\t \t \t   " };
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
            BuildDropPath = TestBuildDropPath,
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
            BuildDropPath = TestBuildDropPath,
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
    /// Test for ensuring GenerateSbom assigns a default Verbosity
    /// level when null input is provided.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Null_Verbosity()
    {
        // Arrange
        // If Verbosity is null, the task should assign a default value should be 'Information'
        var task = new GenerateSbom
        {
            BuildDropPath = TestBuildDropPath,
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

        // Assert
        Assert.IsTrue(result);
        Assert.AreEqual("Information", task.Verbosity);
    }

    /// <summary>
    /// Test for ensuring GenerateSbom assigns a default Verbosity for
    /// unrecognized input.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Invalid_Verbosity()
    {
        // Arrange
        // If an invalid Verbosity is specified, the default value should be Information.
        var task = new GenerateSbom
        {
            BuildDropPath = TestBuildDropPath,
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

        // Assert
        Assert.IsTrue(result);
        Assert.AreEqual("Information", task.Verbosity);
    }

    /// <summary>
    /// Test to ensure GenerateSbom correctly parses and provides each EventLevel verbosity
    /// values to the SBOM API.
    /// </summary>
    [TestMethod]
    [DataRow("FATAL", "Fatal")]
    [DataRow("information", "Information")]
    [DataRow("vErBose", "Verbose")]
    [DataRow("Warning", "Warning")]
    [DataRow("eRRor", "Error")]
    [DataRow("DeBug", "Verbose")]
    public void Sbom_Generation_Assigns_Correct_Verbosity_IgnoreCase(string inputVerbosity, string mappedVerbosity)
    {
        // Arrange
        var task = new GenerateSbom
        {
            BuildDropPath = TestBuildDropPath,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = inputVerbosity,
            ManifestInfo = this.SbomSpecification,
            BuildEngine = this.buildEngine.Object,
#if NET472
            SbomToolPath = SbomToolPath,
#endif
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result, $"result: {result} is not set to true.");
        Assert.AreEqual(mappedVerbosity, task.Verbosity);
    }

    private static void Xcopy(string sourceDir, string targetDir)
    {
        foreach (var dirPath in Directory.GetDirectories(sourceDir, "*.*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(dirPath.Replace(sourceDir, targetDir));
        }

        foreach (var newPath in Directory.GetFiles(sourceDir, "*.*", SearchOption.AllDirectories))
        {
            File.Copy(newPath, newPath.Replace(sourceDir, targetDir), true);
        }
    }
}
