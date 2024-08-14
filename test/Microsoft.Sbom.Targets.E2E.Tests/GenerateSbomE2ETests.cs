// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.E2E.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using Castle.Core.Internal;
using Microsoft.Build.Evaluation;
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
    private static string manifestDirPath = projectDirectory;
    private string manifestPath;
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

            var manifestFolderPath = Path.Combine(manifestDirPath, "_manifest");
            if (Directory.Exists(manifestFolderPath))
            {
                Directory.Delete(manifestFolderPath, true);
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

        if (expectedPackageName.IsNullOrEmpty())
        {
            expectedPackageName = assemblyName;
        }

        if (expectedVersion.IsNullOrEmpty())
        {
            expectedVersion = "1.0.0";
        }
    }

    private void RestoreBuildPack(Project sampleProject)
    {
        var logger = new ConsoleLogger();

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Finally, pack the project
        var pack = sampleProject.Build("Pack", new[] { logger });
        Assert.IsTrue(pack, "Failed to pack the project");
    }

    private void ExtractPackage()
    {
        // Unzip the contents of the NuGet package
        var nupkgPath = Path.Combine(projectDirectory, "bin", configuration);
        var nupkgFile = Path.Combine(nupkgPath, $"{expectedPackageName}.{expectedVersion}.nupkg");
        var zipFile = Path.Combine(nupkgPath, $"{expectedPackageName}.{expectedVersion}.zip");
        var extractPath = Path.Combine(projectDirectory, "bin", configuration, $"{Guid.NewGuid()}.temp");

        // Rename the .nupkg file to .zip
        File.Copy(nupkgFile, zipFile, true);

        // Extract the .zip file
        ZipFile.ExtractToDirectory(zipFile, extractPath);

        manifestPath = Path.Combine(extractPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");
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
        ExtractPackage();

        // Validate the SBOM exists in the package.
        Assert.IsTrue(File.Exists(manifestPath));
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
        ExtractPackage();

        // Validate the SBOM exists in the package.
        Assert.IsTrue(File.Exists(manifestPath));
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
        ExtractPackage();

        // Validate the SBOM exists in the package.
        Assert.IsTrue(File.Exists(manifestPath));
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
        ExtractPackage();

        // Ensure the manifest file was not created
        Assert.IsTrue(!File.Exists(manifestPath));
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
        sampleProject.SetProperty("TargetFrameworks", "net472;net6.0");

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM exists in the package.
        Assert.IsTrue(File.Exists(manifestPath));
    }
}
