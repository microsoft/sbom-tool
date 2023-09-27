﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.ComponentModel;
using System.Text.RegularExpressions;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils.Tests;

[TestClass]
public class InternalMetadataProviderIdentityExtensionsTests
{
    [TestMethod]
    public void GetGenerationTimestamp_Default_Test()
    {
        var mdProviderMock = new Mock<IInternalMetadataProvider>();
        object time = null;
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.GenerationTimestamp, out time))
            .Returns(false);

        var timestamp = mdProviderMock.Object.GetGenerationTimestamp();

        Assert.IsNotNull(timestamp);
        var parsedDate = new DateTimeOffsetConverter().ConvertFromString(timestamp);
        Assert.IsNotNull(parsedDate);
    }

    [TestMethod]
    public void GetGenerationTimestamp_Override_Test()
    {
        var mdProviderMock = new Mock<IInternalMetadataProvider>();
        object time = "time";
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.GenerationTimestamp, out time))
            .Returns(true);

        var timestamp = mdProviderMock.Object.GetGenerationTimestamp();

        Assert.IsNotNull(timestamp);
        Assert.IsTrue(timestamp.Equals("time"));
    }

    [TestMethod]
    public void GetPackageVersion_WherePackageVersionIsValid_ReturnPackageVersion()
    {
        var mdProviderMock = new Mock<IInternalMetadataProvider>();
        var packageVersion = "version";

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageVersion, out packageVersion))
            .Returns(true);

        var actualPackageVersion = mdProviderMock.Object.GetPackageVersion();

        Assert.AreEqual(packageVersion, actualPackageVersion);
    }

    [TestMethod]
    [DataRow(null, false)]
    [DataRow("", false)]
    [DataRow(" ", false)]
    public void GetPackageVersion_WherePackageVersionIsNullOrWhitespace_ReturnBuildId(string packageVersion, bool versionExist)
    {
        var buildId = "buildId";
        var mdProviderMock = new Mock<IInternalMetadataProvider>();

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageVersion, out packageVersion))
            .Returns(versionExist);
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.Build_BuildId, out buildId))
            .Returns(true);

        var actualPackageVersion = mdProviderMock.Object.GetPackageVersion();

        Assert.AreEqual(buildId, actualPackageVersion);
    }

    [TestMethod]
    [DataRow(null, false)]
    [DataRow("", false)]
    [DataRow(" ", false)]
    public void GetPackageVersion_WherePackageVersionAndBuildIdIsInvalid_Throw(string buildId, bool buildIdExist)
    {
        string packageVersion = null;
        var mdProviderMock = new Mock<IInternalMetadataProvider>();

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageVersion, out packageVersion))
            .Returns(false);
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.Build_BuildId, out buildId))
            .Returns(buildIdExist);

        try
        {
            var actualPackageVersion = mdProviderMock.Object.GetPackageVersion();
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.AreEqual(typeof(ArgumentException), e.GetType());
        }
    }

    [TestMethod]
    public void GetPackageName_WherePackageNameIsValid_ReturnPackageName()
    {
        var mdProviderMock = new Mock<IInternalMetadataProvider>();
        var packageName = "name";

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageName, out packageName))
            .Returns(true);

        var actualPackageName = mdProviderMock.Object.GetPackageName();

        Assert.AreEqual(packageName, actualPackageName);
    }

    [TestMethod]
    [DataRow(null, false)]
    [DataRow("", false)]
    [DataRow(" ", false)]
    public void GetPackageName_WherePackageNameIsNullOrWhitespace_ReturnBuildDef(string packageName, bool nameExist)
    {
        var buildDef = "buildDef";
        var mdProviderMock = new Mock<IInternalMetadataProvider>();

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageVersion, out packageName))
            .Returns(nameExist);
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.Build_DefinitionName, out buildDef))
            .Returns(true);

        var actualPackageName = mdProviderMock.Object.GetPackageName();

        Assert.AreEqual(buildDef, actualPackageName);
    }

    [TestMethod]
    [DataRow(null, false)]
    [DataRow("", false)]
    [DataRow(" ", false)]
    public void GetPackageName_WherePackageNameAndBuildDefIsInvalid_Throw(string buildDef, bool buildDefExist)
    {
        string packageVersion = null;
        var mdProviderMock = new Mock<IInternalMetadataProvider>();

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageName, out packageVersion))
            .Returns(false);
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.Build_BuildId, out buildDef))
            .Returns(buildDefExist);

        try
        {
            var actualPackageVersion = mdProviderMock.Object.GetPackageName();
            Assert.Fail();
        }
        catch (Exception e)
        {
            Assert.AreEqual(typeof(ArgumentException), e.GetType());
        }
    }

    [TestMethod]
    public void GetSwidPurl_Succeeds()
    {
        var mdProviderMock = new Mock<IInternalMetadataProvider>();
        var tagId = Guid.NewGuid();

        var packageName = "name";
        var packageVersion = "1.0.0";
        object packageSupplier = "Microsoft";
        var namespaceUri = new Uri("https://test.com/");
        var expectedSwidPurlPattern = @"^pkg:swid\/Microsoft\/test.com\/name@1\.0\.0\?tag_id=.*";

        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageSupplier, out packageSupplier))
            .Returns(true);
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageVersion, out packageVersion))
            .Returns(true);
        mdProviderMock.Setup(m => m.TryGetMetadata(MetadataKey.PackageName, out packageName))
            .Returns(true);
        mdProviderMock.Setup(m => m.GetSBOMNamespaceUri())
        .Returns(namespaceUri.ToString);

        var actualSwidPurl = mdProviderMock.Object.GetSwidTagId();

        Assert.IsTrue(Regex.IsMatch(actualSwidPurl, expectedSwidPurlPattern));
    }
}
