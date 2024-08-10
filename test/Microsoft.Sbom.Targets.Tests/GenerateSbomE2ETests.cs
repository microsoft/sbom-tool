// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests;

using System;
using System.IO;
using System.IO.Compression;
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
     * into a .NET project, building it, packing it, and validating the generated SBOM contents.
     *
     * NOTE: These tests should be run serially, as there are issues when multiple tests reference the same
     * .csproj file through the Project object at the same time.
     */

    //#if NET472
    private static string projectDirectory = Path.Combine(Directory.GetCurrentDirectory(), "ProjectSamples", "ProjectSample1");

    private GeneratedSbomValidator generatedSbomValidator;
    private static string sbomSpecificationName = "SPDX";
    private static string sbomSpecificationVersion = "2.2";
    private static string sbomSpecificationDirectoryName = $"{sbomSpecificationName}_{sbomSpecificationVersion}".ToLowerInvariant();
    private static string manifestDirPath = projectDirectory;
    private string buildDropPath;
    private string manifestPath;
    private string expectedPackageName;
    private string expectedVersion;
    private string expectedSupplier;
    private string assemblyName;
    private string expectedNamespace;
    private string configuration;
    private object project;

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
        generatedSbomValidator = new GeneratedSbomValidator($"{sbomSpecificationName}:{sbomSpecificationVersion}");
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        project = new Project(projectFile);
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

            project = null;
        }
        catch (Exception ex)
        {
            Assert.Fail($"Failed to cleanup output directories. {ex}");
        }
    }

    private void GetDefaultProperties(Project sampleProject)
    {
        expectedPackageName = sampleProject.GetPropertyValue("PackageId");
        expectedVersion = sampleProject.GetPropertyValue("Version");
        expectedSupplier = sampleProject.GetPropertyValue("Authors");
        assemblyName = sampleProject.GetPropertyValue("AssemblyName");
        configuration = sampleProject.GetPropertyValue("Configuration");

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
        var extractPath = Path.Combine(projectDirectory, "bin", configuration, $"{Guid.NewGuid()}.temp");

        // Rename the .nupkg file to .zip
        File.Copy(nupkgFile, zipFile, true);

        // Extract the .zip file
        ZipFile.ExtractToDirectory(zipFile, extractPath);

        manifestPath = Path.Combine(extractPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");
        buildDropPath = extractPath;
    }

    [TestMethod]
    public void SbomGenerationSucceedsForDefaultProperties()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM contents inside the package.
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
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Manually set the ManifestDirPath
        sampleProject.SetProperty("SbomGenerationManifestDirPath", manifestDirPath);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        manifestPath = Path.Combine(manifestDirPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");

        // Check if the SBOM exists in the ManifestDirPath
        Assert.IsTrue(File.Exists(manifestPath));

        // Validate the SBOM contents inside the NuGet package.
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
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

        // Manually set the NamespaceUriUniquePart
        var namespaceUriUniquePart = Guid.NewGuid().ToString();
        sampleProject.SetProperty("SbomGenerationNamespaceUriUniquePart", namespaceUriUniquePart);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM contents inside the NuGet package.
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
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

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

        // Validate the SBOM contents inside the NuGet package.
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
    public void SbomGenerationFailsForInvalidNamespaceUri()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

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
        //Arrange
        // Create a Project object for ProjectSample1
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

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
        //Arrange
        // Create a Project object for ProjectSample1
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set the TargetFrameworks property to empty. By default, it sets this property to net6.0 and net8.0, which fails for net8.0 builds.
        sampleProject.SetProperty("TargetFrameworks", string.Empty);

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
        //Arrange
        // Create a Project object for ProjectSample1
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set require params
        sampleProject.SetProperty("TargetFramework", string.Empty);
        sampleProject.SetProperty("TargetFrameworks", "net472;net6.0");

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        // Validate the SBOM contents inside the NuGet package.
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
    public void SbomGenerationSucceedsForValidManifestDirPathInMultiTargetedProject()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var sampleProject = (Project)project;

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Set require params
        sampleProject.SetProperty("TargetFramework", string.Empty);
        sampleProject.SetProperty("TargetFrameworks", "net472;net6.0");
        sampleProject.SetProperty("SbomGenerationManifestDirPath", manifestDirPath);

        // Restore, build, and pack the project
        RestoreBuildPack(sampleProject);

        // Extract the NuGet package
        ExtractPackage();

        manifestPath = Path.Combine(manifestDirPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");

        // Check if the SBOM exists in the ManifestDirPath
        Assert.IsTrue(File.Exists(manifestPath));

        // Validate the SBOM contents inside the NuGet package.
        this.generatedSbomValidator.AssertSbomIsValid(manifestPath,
            buildDropPath,
            expectedPackageName,
            expectedVersion,
            expectedSupplier,
            expectedNamespace,
            null,
            projectDirectory);
    }
}
