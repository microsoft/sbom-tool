// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests;

using System;
using System.IO;
using Castle.Core.Internal;
using Microsoft.Build.Evaluation;
using Microsoft.Build.Locator;
using Microsoft.Build.Logging;
using Microsoft.Sbom.Targets.Tests.Utility;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static System.Net.WebRequestMethods;

[TestClass]
public class GenerateSbomE2ETests
{
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

    [TestInitialize]
    public void SetupLocator()
    {
        if (MSBuildLocator.CanRegister)
        {
            var instance = MSBuildLocator.RegisterDefaults();
        }

        SetupProperties();
    }

    public void SetupProperties()
    {
        this.generatedSbomValidator = new GeneratedSbomValidator($"{sbomSpecificationName}:{sbomSpecificationVersion}");
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
        }
        catch (Exception ex)
        {
            Assert.Fail($"Failed to cleanup output directories. {ex}");
        }
    }

    private void GetDefaultProperties(Project sampleProject)
    {
        buildDropPath = Path.Combine(projectDirectory, sampleProject.GetPropertyValue("OutDir"));
        manifestPath = Path.Combine(buildDropPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");
        expectedPackageName = sampleProject.GetPropertyValue("PackageId");
        expectedVersion = sampleProject.GetPropertyValue("Version");
        expectedSupplier = sampleProject.GetPropertyValue("Authors");
        assemblyName = sampleProject.GetPropertyValue("AssemblyName");

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

    [TestMethod]
    public void SbomGenerationSucceedsForDefaultProperties()
    {
        //Arrange
        // Create a Project object for ProjectSample1
        var logger = new ConsoleLogger();
        var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
        var sampleProject = new Project(projectFile);

        // Get all the expected default properties
        GetDefaultProperties(sampleProject);

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Validate the SBOM contents
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

        // Manually set the ManifestDirPath
        sampleProject.SetGlobalProperty("SbomGenerationManifestDirPath", manifestDirPath);
        manifestPath = Path.Combine(manifestDirPath, "_manifest", sbomSpecificationDirectoryName, "manifest.spdx.json");

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Validate the SBOM contents
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

        // Manually set the ManifestDirPath
        var namespaceUriUniquePart = Guid.NewGuid().ToString();
        sampleProject.SetGlobalProperty("SbomGenerationNamespaceUriUniquePart", namespaceUriUniquePart);

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Validate the SBOM contents
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

        // Set require params
        buildDropPath = Path.Combine(projectDirectory, "bin", "debug", "net8.0");
        expectedPackageName = "SampleName";
        expectedVersion = "3.2.5";
        expectedSupplier = "SampleSupplier";
        expectedNamespace = "https://example.com";

        sampleProject.SetGlobalProperty("SbomGenerationBuildDropPath", buildDropPath);
        sampleProject.SetGlobalProperty("SbomGenerationPackageName", expectedPackageName);
        sampleProject.SetGlobalProperty("SbomGenerationPackageVersion", expectedVersion);
        sampleProject.SetGlobalProperty("SbomGenerationPackageSupplier", expectedSupplier);
        sampleProject.SetGlobalProperty("SbomGenerationNamespaceBaseUri", expectedNamespace);

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsTrue(build, "Failed to build the project");

        // Validate the SBOM contents
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

        // Restore the project to create project.assets.json file
        var restore = sampleProject.Build("Restore", new[] { logger });
        Assert.IsTrue(restore, "Failed to restore the project");

        // Next, build the project
        var build = sampleProject.Build(logger);
        Assert.IsFalse(build, "Failed to build the project");
    }

    //[TestMethod]
    //public void SbomGenerationBuildSucceedsForMultiTargetedProject()
    //{
    //    //Arrange
    //    // Create a Project object for ProjectSample1
    //    var logger = new ConsoleLogger();
    //    var projectFile = Path.Combine(projectDirectory, "ProjectSample1.csproj");
    //    var sampleProject = new Project(projectFile);

    //    // Get all the expected default properties
    //    //GetDefaultProperties(sampleProject);

    //    // Set require params
    //    var projectProperty = sampleProject.GetProperty("TargetFramework");
    //    sampleProject.RemoveProperty(projectProperty);
    //    sampleProject.SetProperty("TargetFrameworks", "net8.0;net6.0");
    //    sampleProject.SetProperty("GeneratePackageOnBuild", "false");
    //    sampleProject.Save();

    //    // Restore the project to create project.assets.json file
    //    var restore = sampleProject.Build("Restore", new[] { logger });
    //    Assert.IsTrue(restore, "Failed to restore the project");

    //    // Next, build the project
    //    var build = sampleProject.Build(logger);
    //    Assert.IsTrue(build, "Failed to build the project");

    //    // Validate the SBOM contents
    //    //this.generatedSbomValidator.AssertSbomIsValid(manifestPath,
    //    //    buildDropPath,
    //    //    expectedPackageName,
    //    //    expectedVersion,
    //    //    expectedSupplier,
    //    //    expectedNamespace,
    //    //    null,
    //    //    projectDirectory);
    //}

    //#endif
}
