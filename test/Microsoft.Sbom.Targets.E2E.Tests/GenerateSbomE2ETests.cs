// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.E2E.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Build.Evaluation;
using Microsoft.Build.Framework;
using Microsoft.Build.Locator;
using Microsoft.Build.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class GenerateSbomE2ETests
{
    /*
     * The following tests validate the end-to-end workflow for importing the Microsoft.Sbom.Targets.targets
     * into a .NET project, building it, packing it, and validating the generated SBOM contents.
     */

    private static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    private static string projectDirectory = Path.Combine(Directory.GetCurrentDirectory(), "ProjectSamples", "ProjectSample1");
    private static string sbomToolPath = Path.Combine(Directory.GetCurrentDirectory(), "sbom-tool");
    private static string generateSbomTaskPath = Path.Combine(Directory.GetCurrentDirectory(), "Microsoft.Sbom.Targets.dll");

    private static string sbomSpecificationName = "SPDX";
    private static string sbomSpecificationVersion = "2.2";
    private static string sbomSpecificationDirectoryName = $"{sbomSpecificationName}_{sbomSpecificationVersion}".ToLowerInvariant();
    private string expectedPackageName;
    private string expectedVersion;
    private string expectedSupplier;
    private string assemblyName;
    private string expectedNamespace;
    private string configuration;

    [TestInitialize]
    public void SetupLocator()
    {
        if (MSBuildLocator.CanRegister)
        {
            MSBuildLocator.RegisterDefaults();
        }
    }

    [TestCleanup]
    public void CleanOutputFolders()
    {
        var binDir = Path.Combine(projectDirectory, "bin");
        var objDir = Path.Combine(projectDirectory, "obj");

        try
        {
            if (Directory.Exists(binDir))
            {
                Directory.Delete(binDir, true);
            }

            if (Directory.Exists(objDir))
            {
                Directory.Delete(objDir, true);
            }

            ProjectCollection.GlobalProjectCollection.UnloadAllProjects();
        }
        catch (Exception ex)
        {
            Assert.Fail($"Failed to cleanup output directories. {ex}");
        }
    }

    private Project SetupSampleProject()
    {
        // Create a Project object for ProjectSample1
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        SetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Set the paths to the sbom-tool CLI tool and Microsoft.Sbom.Targets.dll
        sampleProject.SetProperty("SbomToolBinaryOutputPath", sbomToolPath);
        sampleProject.SetProperty("GenerateSbomTaskAssemblyFilePath", generateSbomTaskPath);

        return sampleProject;
    }

    private void SetDefaultProperties(Project sampleProject)
    {
        expectedPackageName = sampleProject.GetPropertyValue("PackageId");
        expectedVersion = sampleProject.GetPropertyValue("Version");
        assemblyName = sampleProject.GetPropertyValue("AssemblyName");
        configuration = sampleProject.GetPropertyValue("Configuration");

        if (string.IsNullOrEmpty(expectedPackageName))
        {
            expectedPackageName = assemblyName;
        }

        if (string.IsNullOrEmpty(expectedPackageName))
        {
            expectedVersion = "1.0.0";
        }
    }

    private void RestoreBuildPack(Project sampleProject, [CallerMemberName] string callerName = null)
    {
        var logger = new ConsoleLogger();
        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new ILogger[] { GetBinLog(callerName, "Restore"), logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(new ILogger[] { GetBinLog(callerName, "Build"), logger });
        Assert.IsTrue(build, "Failed to build the project");

        // Finally, pack the project
        var pack = sampleProject.Build("Pack", new ILogger[] { GetBinLog(callerName, "Pack"), logger });
        Assert.IsTrue(pack, "Failed to pack the project");
    }

    // binlogs are unique per name, so this ensures distinct names for the different stages
    private BinaryLogger GetBinLog(string callerName, string target) => new BinaryLogger { Parameters = $"{callerName}.{target}.binlog" };

    private void InspectPackageIsWellFormed(bool isManifestPathGenerated = true)
    {
        const string backSlash = "\\";
        const string forwardSlash = "/";
        // Unzip the contents of the NuGet package
        var nupkgPath = Path.Combine(projectDirectory, "bin", configuration);
        var nupkgFile = Path.Combine(nupkgPath, $"{expectedPackageName}.{expectedVersion}.nupkg");
        var manifestRelativePath = Path.Combine("_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json")
            .Replace(backSlash, forwardSlash);

        // Check the content of the NuGet package
        using (var archive = ZipFile.Open(nupkgFile, ZipArchiveMode.Read))
        {
            Assert.IsTrue(archive.Entries.Count() > 0);
            // Nuget's zip code expects forward slashes as path separators.
            Assert.IsTrue(archive.Entries.All(entry => !entry.FullName.Contains(backSlash)));
            Assert.AreEqual(isManifestPathGenerated, archive.Entries.Any(entry => entry.FullName.Equals(manifestRelativePath)));
        }
    }

    [TestMethod]
    public void SbomGenerationSucceedsForDefaultProperties()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        InspectPackageIsWellFormed();
    }

    [TestMethod]
    public void SbomGenerationSucceedsForValidNamespaceBaseUriUniquePart()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Manually set the NamespaceUriUniquePart
        var namespaceUriUniquePart = Guid.NewGuid().ToString();
        sampleProject.SetProperty("SbomGenerationNamespaceUriUniquePart", namespaceUriUniquePart);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        InspectPackageIsWellFormed();
    }

    [TestMethod]
    public void SbomGenerationSucceedsForValidRequiredParams()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Set require params
        expectedPackageName = "SampleName";
        expectedVersion = "3.2.5";
        expectedSupplier = "SampleSupplier";
        expectedNamespace = "https://example.com";

        sampleProject.SetProperty("PackageId", expectedPackageName);
        sampleProject.SetProperty("Version", expectedVersion);
        sampleProject.SetProperty("SbomGenerationPackageName", expectedPackageName);
        sampleProject.SetProperty("SbomGenerationPackageVersion", expectedVersion);
        sampleProject.SetProperty("SbomGenerationPackageSupplier", expectedSupplier);
        sampleProject.SetProperty("SbomGenerationNamespaceBaseUri", expectedNamespace);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        InspectPackageIsWellFormed();
    }

    [TestMethod]
    public void SbomGenerationFailsForInvalidNamespaceUri()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Set invalid namespace
        expectedNamespace = "incorrect_uri";
        sampleProject.SetProperty("SbomGenerationNamespaceBaseUri", expectedNamespace);

        // Restore, build, and pack the project
        var logger = new ConsoleLogger();

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Ensure the packing step fails
        var pack = sampleProject.Build("Pack", new[] { logger });
        Assert.IsFalse(pack, "Packing succeeded when it should have failed");
    }

    [TestMethod]
    public void SbomGenerationFailsForInvalidSupplierName()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Set invalid supplier name
        sampleProject.SetProperty("Authors", string.Empty);
        sampleProject.SetProperty("AssemblyName", string.Empty);
        sampleProject.SetProperty("SbomGenerationPackageSupplier", string.Empty);

        // Restore, build, and pack the project
        var logger = new ConsoleLogger();

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Ensure the packing step fails
        var pack = sampleProject.Build("Pack", new[] { logger });
        Assert.IsFalse(pack, "Packing succeeded when it should have failed");
    }

    [TestMethod]
    public void SbomGenerationSkipsForUnsetGenerateSBOMFlag()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Set the GenerateSBOM property to empty.
        sampleProject.SetProperty("GenerateSBOM", "false");

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        InspectPackageIsWellFormed(isManifestPathGenerated: false);
    }

    [TestMethod]
    public void SbomGenerationSucceedsForMultiTargetedProject()
    {
        if (!IsWindows)
        {
            Assert.Inconclusive("This test is not (yet) supported on non-Windows platforms.");
            return;
        }

        // Create and setup a Project object for ProjectSample1
        var sampleProject = SetupSampleProject();

        // Set multi-target frameworks
        sampleProject.SetProperty("TargetFramework", string.Empty);
        sampleProject.SetProperty("TargetFrameworks", "net472;net8.0");

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        InspectPackageIsWellFormed();
    }
}
