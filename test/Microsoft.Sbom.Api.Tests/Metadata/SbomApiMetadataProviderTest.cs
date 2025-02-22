// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Metadata;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.Metadata;

[TestClass]
public class SbomApiMetadataProviderTest
{
    private Configuration config;
    private SBOMMetadata metadata;

    [TestInitialize]
    public void TestInitialize()
    {
        config = new Configuration
        {
            NamespaceUriUniquePart = new ConfigurationSetting<string>("some-custom-value-here"),
            NamespaceUriBase = new ConfigurationSetting<string>("http://sbom.microsoft")
        };
        metadata = new SBOMMetadata
        {
            BuildId = "buildId",
            PackageName = "packageName",
            PackageVersion = "packageVersion",
            BuildName = "buildName",
            RepositoryUri = "repositoryUri",
            Branch = "branch",
            CommitId = "commitId"
        };
    }

    [TestMethod]
    public void SbomApiMetadataProvider_BuildEnvironmentName_WithMetadata()
    {
        metadata.BuildEnvironmentName = "name";

        var sbomApiMetadataProvider = new SBOMApiMetadataProvider_(metadata, config);
        Assert.AreEqual("name", sbomApiMetadataProvider.BuildEnvironmentName);
    }

    [TestMethod]
    public void SbomApiMetadataProvider_BuildEnvironmentName_WithoutMetadata()
    {
        var sbomApiMetadataProvider = new SBOMApiMetadataProvider_(metadata, config);
        Assert.IsNull(sbomApiMetadataProvider.BuildEnvironmentName);
    }

    [TestMethod]
    public void SbomApiMetadataProvider_GetDocumentNamespaceUri()
    {
        var sbomApiMetadataProvider = new SBOMApiMetadataProvider_(metadata, config);
        Assert.AreEqual("http://sbom.microsoft/packageName/packageVersion/some-custom-value-here", sbomApiMetadataProvider.GetDocumentNamespaceUri());
    }

    [TestMethod]
    public void SbomApiMetadataProvider_WithNullConfiguration_ThrowArgumentNullException()
    {
        Assert.ThrowsException<ArgumentNullException>(() => new SBOMApiMetadataProvider_(metadata, null));
    }

    [TestMethod]
    public void SbomApiMetadataProvider_WithNullMetadata_ThrowArgumentNullException()
    {
        Assert.ThrowsException<ArgumentNullException>(() => new SBOMApiMetadataProvider_(null, config));
    }
}
