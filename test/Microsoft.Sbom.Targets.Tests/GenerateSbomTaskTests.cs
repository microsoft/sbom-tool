using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Sbom.Targets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public class GenerateSbomTaskTests
{
    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;
    private static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    private static readonly string ManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        buildEngine = new Mock<IBuildEngine>();
        errors = new List<BuildErrorEventArgs>();
        buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));

        // Clean up the manifest directory
        if (Directory.Exists(ManifestDirectory))
        {
            Directory.Delete(ManifestDirectory, true);
        }
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated()
    {
        // Let's generate a SBOM for the current assembly
        var sourceDirectory = Path.Combine(CurrentDirectory, "..\\..\\..");

        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            BuildComponentPath = sourceDirectory,
            PackageSupplier = "Microsoft",
            PackageName = "CoseSignTool",
            PackageVersion = "1.0.0",
            NamespaceBaseUri = "https://base.uri",
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);

        var manifestPath = Path.Combine(ManifestDirectory, "spdx_2.2", "manifest.spdx.json");
        Assert.IsTrue(Path.Exists(manifestPath));
    }
}
