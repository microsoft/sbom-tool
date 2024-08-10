// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests;

using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Castle.Core.Internal;
using Microsoft.Build.Evaluation;
using Microsoft.Build.Locator;
using Microsoft.Build.Logging;
using Microsoft.Sbom.Targets.Tests.Utility;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class GenerateSbomE2ETests
{
    /*
     * The following tests validate the end-to-end workflow for importing the Microsoft.Sbom.Targets.targets
     * into a .NET project, building it, and validating the generated SBOM contents.
     *
     * NOTE: These tests should be run serially, as the MSBuild API likes it when there is one Project object referencing a single
     * .csproj. However, due to restrictions on where the MSBuildLocator is called, we must create a Project instance per test.
     */

    //#if NET472
    private static string projectDirectory = Path.Combine(Directory.GetCurrentDirectory(), "ProjectSamples", "ProjectSample1");

    private GeneratedSbomValidator generatedSbomValidator;
    private static string sbomSpecificationName = "SPDX";
    private static string sbomSpecificationVersion = "2.2";
    private static string sbomSpecificationDirectoryName = $"{sbomSpecificationName}_{sbomSpecificationVersion}".ToLowerInvariant();
    private static string manifestDirPath = projectDirectory;
    private static string buildDropPath;
    private static string manifestPath;
    private static string expectedPackageName;
    private static string expectedVersion;
    private static string expectedSupplier;
    private static string assemblyName;
    private static string expectedNamespace;
    private static string configuration;
    private static string buildOutputFolder;
    private static string targetFramework;

    [TestInitialize]
    public void SetupLocator()
    {
        if (MSBuildLocator.CanRegister)
        {
            MSBuildLocator.RegisterDefaults();
        }

        SetupProperties();
    }

    public void SetupProperties()
    {
        this.generatedSbomValidator = new GeneratedSbomValidator($"{sbomSpecificationName}:{sbomSpecificationVersion}");
    }

    //[TestCleanup]
    //public void CleanOutputFolders()
    //{
    //    var binDir = Path.Combine(projectDirectory, "bin");
    //    var objDir = Path.Combine(projectDirectory, "obj");

    //    try
    //    {
    //        if (Directory.Exists(binDir))
    //        {
    //            Directory.Delete(binDir, true);
    //        }

    //        if (Directory.Exists(objDir))
    //        {
    //            Directory.Delete(objDir, true);
    //        }

    //        var manifestFolderPath = Path.Combine(manifestDirPath, "_manifest");
    //        if (Directory.Exists(manifestFolderPath))
    //        {
    //            Directory.Delete(manifestFolderPath, true);
    //        }
    //    }
    //    catch (Exception ex)
    //    {
    //        Assert.Fail($"Failed to cleanup output directories. {ex}");
    //    }
    //}

    // Make all tests do packing
    // one case where GenerateSBOM is set to false and SBOM properties are set. THis should not generate manifest
    private void GetDefaultProperties(Project sampleProject)
    {
        buildDropPath = Path.Combine(projectDirectory, sampleProject.GetPropertyValue("OutDir"));
        manifestPath = Path.Combine(buildDropPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");
        expectedPackageName = sampleProject.GetPropertyValue("PackageId");
        expectedVersion = sampleProject.GetPropertyValue("Version");
        expectedSupplier = sampleProject.GetPropertyValue("Authors");
        assemblyName = sampleProject.GetPropertyValue("AssemblyName");
        configuration = sampleProject.GetPropertyValue("Configuration");
        buildOutputFolder = sampleProject.GetPropertyValue("BuildOutputTargetFolder");
        targetFramework = sampleProject.GetPropertyValue("TargetFramework");

        if (expectedPackageName.IsNullOrEmpty())
        {
            expectedPackageName = assemblyName;
        }

        if (expectedSupplier.IsNullOrEmpty())
        {
            expectedSupplier = assemblyName;
        }

        if (expectedVersion.IsNullOrEmpty())
        {
            expectedVersion = "1.0.0";
        }

        expectedNamespace = $"http://spdx.org/spdxdocs/{expectedPackageName}";
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
        var extractPath = Path.Combine(projectDirectory, "bin", configuration, "temp");

        // Rename the .nupkg file to .zip
        File.Copy(nupkgFile, zipFile, true);

        // Extract the .zip file
        ZipFile.ExtractToDirectory(zipFile, extractPath);

        manifestPath = Path.Combine(extractPath, buildOutputFolder, targetFramework, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");
        buildDropPath = Path.Combine(extractPath, buildOutputFolder, targetFramework); // TODO: change this after updating our .targets file to generate 1 sbom per package
    }

    [TestMethod]
    public void SbomGenerationSucceedsForDefaultProperties()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);
        // Set the TargetFrameworks property to empty. By default, it sets to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM contents inside the package. TODO: update this based on updating our .targets to generate 1 sbom per package
        this.generatedSbomValidator.AssertSbomIsValid(manifestPath,
            buildDropPath,
            expectedPackageName,
            expectedVersion,
            expectedSupplier,
            expectedNamespace,
            null,
            projectDirectory);
    }

    [TestMethod]
    public void SbomGenerationSucceedsForValidManifestDirPath()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);
        // Set the TargetFrameworks property to empty. By default, it sets to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Manually set the ManifestDirPath
        sampleProject.SetGlobalProperty("SbomGenerationManifestDirPath", manifestDirPath);
        manifestPath = Path.Combine(manifestDirPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Check if the SBOM exists in the ManifestDirPath
        Assert.IsTrue(File.Exists(manifestPath));

        // Validate the SBOM contents inside the NuGet package: TODO: update later
        this.generatedSbomValidator.AssertSbomIsValid(manifestPath,
            buildDropPath,
            expectedPackageName,
            expectedVersion,
            expectedSupplier,
            expectedNamespace,
            null,
            projectDirectory);
    }

    [TestMethod]
    public void SbomGenerationSucceedsForValidNamespaceBaseUriUniquePart()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);
        // Set the TargetFrameworks property to empty. By default, it sets to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Manually set the ManifestDirPath
        var namespaceUriUniquePart = Guid.NewGuid().ToString();
        sampleProject.SetGlobalProperty("SbomGenerationNamespaceUriUniquePart", namespaceUriUniquePart);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM contents inside the NuGet package. TODO: update later
        this.generatedSbomValidator.AssertSbomIsValid(manifestPath,
            buildDropPath,
            expectedPackageName,
            expectedVersion,
            expectedSupplier,
            expectedNamespace,
            namespaceUriUniquePart,
            projectDirectory);
    }

    [TestMethod]
    public void SbomGenerationSucceedsForValidRequiredParams()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);
        // Set the TargetFrameworks property to empty. By default, it sets to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Set require params
        buildDropPath = Path.Combine(projectDirectory, "bin", "debug", "net6.0");
        expectedPackageName = "SampleName";
        expectedVersion = "3.2.5";
        expectedSupplier = "SampleSupplier";
        expectedNamespace = "https://example.com";

        sampleProject.SetGlobalProperty("SbomGenerationBuildDropPath", buildDropPath);
        sampleProject.SetGlobalProperty("SbomGenerationPackageName", expectedPackageName);
        sampleProject.SetGlobalProperty("SbomGenerationPackageVersion", expectedVersion);
        sampleProject.SetGlobalProperty("SbomGenerationPackageSupplier", expectedSupplier);
        sampleProject.SetGlobalProperty("SbomGenerationNamespaceBaseUri", expectedNamespace);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM contents inside the NuGet package. TODO: update later
        this.generatedSbomValidator.AssertSbomIsValid(manifestPath,
            buildDropPath,
            expectedPackageName,
            expectedVersion,
            expectedSupplier,
            expectedNamespace,
            null,
            projectDirectory);
    }

    [TestMethod]
    public void SbomGenerationFailsForMissingBuildOutputTargetFolder()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Set the BuildOutputTargetFolder property to empty.
        sampleProject.SetGlobalProperty("BuildOutputTargetFolder", string.Empty);
        // Set the TargetFrameworks property to empty. By default, it sets to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsFalse(build, "Build succeeded when it should have failed.");
    }

    [TestMethod]
    public void SbomGenerationSkipsForUnsetGenerateSBOMFlag()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Set the TargetFrameworks property to empty. By default, it sets to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Set the BuildOutputTargetFolder property to empty.
        sampleProject.SetGlobalProperty("GenerateSBOM", "false");

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Ensure the _manifest folder was not created
        var outDir = sampleProject.GetPropertyValue("OutDir");
        var pathToSbom = Path.Combine(projectDirectory, outDir, "_manifest");
        Assert.IsTrue(!Directory.Exists(pathToSbom));
    }

    [TestMethod]
    public void SbomGenerationSucceedsForMultiTargetedProject()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);
        // Set require params
        sampleProject.SetProperty("TargetFramework", string.Empty);
        sampleProject.SetProperty("TargetFrameworks", "net472;net6.0");

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        //// Check Sboms per framework
        //var targetFrameworks = new string[] { "net472", "net6.0" };

        //foreach (var targetFramework in targetFrameworks)
        //{
        //    var buildDropPathTFM = Path.Combine(projectDirectory, "bin", "debug", targetFramework);
        //    var manifestPathTFM = Path.Combine(buildDropPathTFM, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");
        //    this.generatedSbomValidator.AssertSbomIsValid(manifestPathTFM,
        //       buildDropPathTFM,
        //       expectedPackageName,
        //       expectedVersion,
        //       expectedSupplier,
        //       expectedNamespace,
        //       null,
        //       projectDirectory);
        //}
    }
}
