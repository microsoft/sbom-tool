// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Metadata;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.Config;

[TestClass]
public class SBOMConfigTests
{
    private readonly Mock<IManifestConfigHandler> configHandler;
    private readonly Configuration config;
    private readonly Mock<ILogger> logger;
    private readonly Mock<IRecorder> recorder;
    private readonly LocalMetadataProvider localMetadataProvider;

    public SBOMConfigTests()
    {
        configHandler = new Mock<IManifestConfigHandler>();
        config = new Configuration
        {
            PackageName = new ConfigurationSetting<string>("the-package-name"),
            PackageVersion = new ConfigurationSetting<string>("the-package-version"),
            NamespaceUriUniquePart = new ConfigurationSetting<string>("some-custom-value-here"),
            NamespaceUriBase = new ConfigurationSetting<string>("http://sbom.microsoft")
        };

        logger = new Mock<ILogger>();
        recorder = new Mock<IRecorder>();
        localMetadataProvider = new LocalMetadataProvider(config);
    }

    [TestMethod]
    public void SBOMConfig_DefaultMetadataProvider_Returned()
    {
        var metadataProviders = new IMetadataProvider[] { localMetadataProvider };
        var sbomConfigs = CreateSbomConfigs(metadataProviders);

        var uri = sbomConfigs.GetSBOMNamespaceUri();

        Assert.AreEqual(localMetadataProvider.GetDocumentNamespaceUri(), uri);
    }

    [TestMethod]
    public void SBOMConfig_BuildEnvironmentMetadataProvider_Returned()
    {
        var sbomMetadata = new SBOMMetadata
        {
            PackageName = "sbom-package-name",
            PackageVersion = "sbom-package-version",
            BuildEnvironmentName = "the-build-envsdfgsdg"
        };

        var sbomApiMetadataProvider = new SBOMApiMetadataProvider(sbomMetadata, config);
        var metadataProviders = new IMetadataProvider[] { localMetadataProvider, sbomApiMetadataProvider };
        var sbomConfigs = CreateSbomConfigs(metadataProviders);

        var uri = sbomConfigs.GetSBOMNamespaceUri();

        Assert.AreEqual(sbomApiMetadataProvider.GetDocumentNamespaceUri(), uri);
    }

    [TestMethod]
    public void SBOMConfig_NoBuildEnvironmentName_DefaultMetadataProvider_Returned()
    {
        var sbomMetadata = new SBOMMetadata
        {
            PackageName = "sbom-package-name",
            PackageVersion = "sbom-package-version",
            BuildEnvironmentName = null
        };

        var sbomApiMetadataProvider = new SBOMApiMetadataProvider(sbomMetadata, config);
        var metadataProviders = new IMetadataProvider[] { localMetadataProvider, sbomApiMetadataProvider };
        var sbomConfigs = CreateSbomConfigs(metadataProviders);

        var uri = sbomConfigs.GetSBOMNamespaceUri();

        Assert.AreEqual(localMetadataProvider.GetDocumentNamespaceUri(), uri);
    }

    private ISbomConfigProvider CreateSbomConfigs(IMetadataProvider[] metadataProviders) =>
        new SbomConfigProvider(
            manifestConfigHandlers: new IManifestConfigHandler[] { configHandler.Object },
            metadataProviders: metadataProviders,
            logger: logger.Object,
            recorder: recorder.Object);
}
