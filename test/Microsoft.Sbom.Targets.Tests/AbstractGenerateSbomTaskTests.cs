using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Targets;
using Microsoft.Sbom.Targets.Tests.Utility;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Newtonsoft.Json;

namespace Microsoft.Sbom.Targets.Tests;

/// <summary>
/// Base class for testing SBOM generation through the GenerateSbomTask.
/// </summary>
[TestClass]
public abstract class AbstractGenerateSbomTaskTests
{
    internal abstract SbomSpecification SbomSpecification { get; }

    internal static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    internal static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    internal static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temp");
    internal const string PackageSupplier = "Test-Microsoft";
    internal const string PackageName = "CoseSignTool";
    internal const string PackageVersion = "0.0.1";
    internal const string NamespaceBaseUri = "https://base0.uri";

    internal Mock<IBuildEngine> BuildEngine;
    internal List<BuildErrorEventArgs> Errors;
    internal string ManifestPath;
    internal GeneratedSbomValidator GeneratedSbomValidator;

    internal string SbomSpecificationDirectoryName => $"{this.SbomSpecification.Name}_{this.SbomSpecification.Version}";

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        this.BuildEngine = new Mock<IBuildEngine>();
        this.Errors = new List<BuildErrorEventArgs>();
        this.BuildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => Errors.Add(e));

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

        this.ManifestPath = Path.Combine(DefaultManifestDirectory, this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        this.GeneratedSbomValidator = new(this.SbomSpecification);
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri);
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated_In_Specified_Location()
    {
        var manifestDirPath = Path.Combine(TemporaryDirectory, "sub-directory");
        Directory.CreateDirectory(manifestDirPath);
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            ManifestDirPath = manifestDirPath,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);

        this.ManifestPath = Path.Combine(manifestDirPath, "_manifest", this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri);
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_BuildDropPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_BuildComponentPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            BuildComponentPath = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
        Assert.IsFalse(Directory.Exists(DefaultManifestDirectory));
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_ExternalDocumentListFile()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            ExternalDocumentListFile = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
        Assert.IsFalse(Directory.Exists(DefaultManifestDirectory));
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_ManifestDirPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            ManifestDirPath = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
        Assert.IsFalse(Directory.Exists(DefaultManifestDirectory));
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated_With_Component_Path()
    {
        // Let's generate a SBOM for the current assembly
        var sourceDirectory = Path.Combine(CurrentDirectory, "..", "..", "..");

        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            BuildComponentPath = sourceDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri, buildComponentPath: sourceDirectory);
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated_With_Unique_Namespace_Part_Defined()
    {
        var uniqueNamespacePart = Guid.NewGuid().ToString();
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            NamespaceUriUniquePart = uniqueNamespacePart,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri, expectedNamespaceUriUniquePart: uniqueNamespacePart);
    }
}
