﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Linq;

namespace Microsoft.Sbom.Api.Tests
{
    /// <summary>
    /// Responsible for testing <see cref="ApiConfigurationBuilder"/>.
    /// </summary>
    [TestClass]
    public class ApiConfigurationBuilderTests
    {
        private const string RootPath = @"D:\TMP";
        private const int MinParallelism = 2;
        private const int DefaultParallelism = 8;
        private const int MaxParallelism = 48;
        private const string PackageName = "packageName";
        private const string PackageVersion = "packageVersion";
        private readonly ApiConfigurationBuilder builder = new ApiConfigurationBuilder();
        private readonly SBOMMetadata metadata = new SBOMMetadata()
        {
            PackageName = PackageName,
            PackageVersion = PackageVersion,
        };

        private readonly RuntimeConfiguration runtime = new RuntimeConfiguration()
        {
            Verbosity = EventLevel.Verbose,
            WorkflowParallelism = DefaultParallelism,
            DeleteManifestDirectoryIfPresent = true
        };

        private readonly string manifestDirPath = "manifestDirPath";
        private readonly List<SBOMFile> files = new List<SBOMFile>();
        private readonly List<SBOMPackage> packages = new List<SBOMPackage>();
        private readonly string externalDocumentRefListFile = "externalDocRef";
        private readonly string componentPath = @"D:\COMPONENT";

        [TestMethod]
        public void GetConfiguration_PopulateAll()
        {
            List<SBOMSpecification> specs = new List<SBOMSpecification>();
            specs.Add(new SBOMSpecification("spdx", "2.2"));

            var expectedManifestInfo = new ManifestInfo()
            {
                Name = "spdx",
                Version = "2.2"
            };

            var config = builder.GetConfiguration(RootPath, manifestDirPath, files, packages, metadata, specs, runtime, externalDocumentRefListFile, componentPath);

            Assert.AreEqual(RootPath, config.BuildDropPath.Value);
            Assert.AreEqual(componentPath, config.BuildComponentPath.Value);
            Assert.AreEqual(manifestDirPath, config.ManifestDirPath.Value);
            Assert.AreEqual(ManifestToolActions.Generate, config.ManifestToolAction);
            Assert.AreEqual(PackageName, config.PackageName.Value);
            Assert.AreEqual(PackageVersion, config.PackageVersion.Value);
            Assert.AreEqual(DefaultParallelism, config.Parallelism.Value);
            Assert.AreEqual(LogEventLevel.Verbose, config.Verbosity.Value);
            Assert.AreEqual(0, config.PackagesList.Value.ToList().Count);
            Assert.AreEqual(0, config.FilesList.Value.ToList().Count);
            Assert.AreEqual(externalDocumentRefListFile, config.ExternalDocumentReferenceListFile.Value);
            Assert.AreEqual(1, config.ManifestInfo.Value.Count);
            Assert.IsTrue(config.ManifestInfo.Value[0].Equals(expectedManifestInfo));

            Assert.AreEqual(SettingSource.SBOMApi, config.BuildDropPath.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.BuildComponentPath.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.ManifestDirPath.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.PackageName.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.PackageVersion.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.Parallelism.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.Verbosity.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.PackagesList.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.FilesList.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.ExternalDocumentReferenceListFile.Source);
            Assert.AreEqual(SettingSource.SBOMApi, config.ManifestInfo.Source);
        }

        [TestMethod]
        public void GetConfiguration_NullProperties()
        {
            var config = builder.GetConfiguration(RootPath, manifestDirPath, null, null, metadata, null, runtime, null, componentPath);

            Assert.IsNull(config.PackagesList);
            Assert.IsNull(config.FilesList);
            Assert.IsNull(config.ExternalDocumentReferenceListFile);
            Assert.IsNull(config.ManifestInfo);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(" ")]
        public void GetConfiguration_NullComponentPath(string componentPath)
        {
            var config = builder.GetConfiguration(RootPath, manifestDirPath, null, null, metadata, null, runtime, null, componentPath);

            Assert.IsNull(config.BuildComponentPath);
        }

        [TestMethod]
        [DataRow(EventLevel.Informational, LogEventLevel.Information)]
        [DataRow(EventLevel.Critical, LogEventLevel.Fatal)]
        [DataRow(EventLevel.Error, LogEventLevel.Error)]
        [DataRow(EventLevel.LogAlways, LogEventLevel.Verbose)]
        [DataRow(EventLevel.Verbose, LogEventLevel.Verbose)]
        [DataRow(EventLevel.Warning, LogEventLevel.Warning)]
        public void GetConfiguration_ShouldMapVerbosity(EventLevel input, LogEventLevel output)
        {
            // This uses EventLevel to avoid exposing the serilog implementation to the caller
            var runtime = new RuntimeConfiguration()
            {
                Verbosity = input
            };

            IConfiguration config = builder.GetConfiguration(
                RootPath, string.Empty, null, null,
                metadata, null, runtime);

            Assert.AreEqual(output, config.Verbosity.Value);
        }

        [TestMethod]
        [DataRow(MinParallelism - 1, DefaultParallelism)]
        [DataRow(MaxParallelism + 1, DefaultParallelism)]
        [DataRow(10, 10)]
        [DataRow(null, DefaultParallelism)]
        public void GetConfiguration_SantizeRuntimeConfig_Parallelism(int? input, int output)
        {
            var runtime = new RuntimeConfiguration()
            {
                Verbosity = EventLevel.Verbose,
            };

            if (input != null)
            {
                runtime.WorkflowParallelism = (int)input;
            }

            var config = builder.GetConfiguration("random", null, null, null, metadata, null, runtime);
            Assert.AreEqual(output, config.Parallelism.Value);
        }

        [TestMethod]
        public void GetConfiguration_DefaultRuntime()
        {
            var defaultRuntime = new RuntimeConfiguration
            {
                WorkflowParallelism = DefaultParallelism,
                Verbosity = EventLevel.Warning,
                DeleteManifestDirectoryIfPresent = false
            };

            var config = builder.GetConfiguration("random", null, null, null, metadata, null, null);
            Assert.AreEqual(defaultRuntime.WorkflowParallelism, config.Parallelism.Value);
            Assert.AreEqual(LogEventLevel.Warning, config.Verbosity.Value);
        }

        [TestMethod]
        [DataRow(" ")]
        [DataRow(null)]
        [ExpectedException(typeof(ArgumentException))]
        public void ThrowArguementExceptionOnRootPathValues(string input)
        {
            builder.GetConfiguration(input, null, null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ThrowArguementNulExceptionOnNullMetadata()
        {
            builder.GetConfiguration("random", null, null, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ThrowArguementExceptionOnSpecificationZero()
        {
            builder.GetConfiguration("random", null, null, null, metadata, new List<SBOMSpecification>(), runtime);
        }
    }
}
