// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Metadata;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PowerArgs;

namespace Microsoft.Sbom.Api.Tests.Metadata;

[TestClass]
public class LocalMetadataProviderTest
{
    private Configuration config;

    [TestInitialize]
    public void TestInitialize()
    {
        config = new Configuration
        {
            NamespaceUriUniquePart = new ConfigurationSetting<string>("some-custom-value-here"),
            NamespaceUriBase = new ConfigurationSetting<string>("http://sbom.microsoft")
        };
    }

    [TestMethod]
    public void LocalMetadataProvider_GetDocumentNamespaceUri()
    {
        config.PackageName = new ConfigurationSetting<string>("name");
        config.PackageVersion = new ConfigurationSetting<string>("version");

        var localMetadataProvider = new LocalMetadataProvider(config);
        Assert.AreEqual("http://sbom.microsoft/name/version/some-custom-value-here", localMetadataProvider.GetDocumentNamespaceUri());
    }

    [TestMethod]
    public void LocalMetadataProvider_WithNullConfiguration_ThrowArgumentNullException()
    {
        Assert.ThrowsException<ArgumentNullException>(() => new LocalMetadataProvider(null));
    }

    [TestMethod]
    public void LocalMetadataProvider_WithNullSupplierAndTimestamp()
    {
        config.PackageName = new ConfigurationSetting<string>("name");
        config.PackageVersion = new ConfigurationSetting<string>("version");
        config.PackageSupplier = null;
        config.GenerationTimestamp = null;

        var localMetadataProvider = new LocalMetadataProvider(config);
        Assert.AreEqual(4, localMetadataProvider.MetadataDictionary.Count);
        Assert.IsFalse(localMetadataProvider.MetadataDictionary.ContainsKey(MetadataKey.PackageSupplier));
        Assert.IsFalse(localMetadataProvider.MetadataDictionary.ContainsKey(MetadataKey.GenerationTimestamp));
    }
}
