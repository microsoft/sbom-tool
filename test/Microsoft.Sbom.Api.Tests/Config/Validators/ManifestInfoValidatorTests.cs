// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Api.Config.Validators;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;

namespace Microsoft.Sbom.Api.Tests.Config.Validators;

[TestClass]
public class ManifestInfoValidatorTests
{
    private readonly Mock<IAssemblyConfig> mockAssemblyConfig = new Mock<IAssemblyConfig>();
    private readonly HashSet<ManifestInfo> supportedManifestInfosForTesting = new HashSet<ManifestInfo>
    {
        Constants.SPDX22ManifestInfo,
        Constants.SPDX30ManifestInfo,
    };

    [DataRow("randomName", "2.2")]
    [DataRow("randomName", "3.0")]
    [DataRow("SPDX", "randomVersion")]
    [DataRow("asodijf", "randomVersion")]
    [TestMethod]
    public void InvalidManifestInfoThrows(string name, string version)
    {
        var invalidManifestInfo = new ManifestInfo
        {
            Name = name,
            Version = version
        };

        IList<ManifestInfo> listOfManifestInfos = new List<ManifestInfo> { invalidManifestInfo };

        var validator = new ManifestInfoValidator(mockAssemblyConfig.Object, supportedManifestInfosForTesting);
        Assert.ThrowsException<ValidationArgException>(() => validator.ValidateInternal("property", listOfManifestInfos, null));
    }

    [DataRow("SPDX", "2.2")]
    [DataRow("SPDX", "3.0")]
    [DataRow("spdx", "2.2")]
    [DataRow("spdx", "3.0")]
    [TestMethod]
    public void ValidManifestInfoPasses(string name, string spdxVersion)
    {
        var validManifestInfo = new ManifestInfo
        {
            Name = name,
            Version = spdxVersion
        };

        IList<ManifestInfo> listOfManifestInfos = new List<ManifestInfo> { validManifestInfo };

        var validator = new ManifestInfoValidator(mockAssemblyConfig.Object, supportedManifestInfosForTesting);
        validator.ValidateInternal("property", listOfManifestInfos, null);
    }

    [TestMethod]
    public void Constructor_ManifestGeneratorProviderIsNull_ThrowsException()
    {
        var e = Assert.ThrowsException<ArgumentNullException>(() => new ManifestInfoValidator(mockAssemblyConfig.Object, null as ManifestGeneratorProvider));
        Assert.AreEqual("manifestGeneratorProvider", e.ParamName);
    }

    [TestMethod]
    public void Constructor_AvailableManifestInfosIsNull_ThrowsException()
    {
        var e = Assert.ThrowsException<ArgumentNullException>(() => new ManifestInfoValidator(mockAssemblyConfig.Object, null as HashSet<ManifestInfo>));
        Assert.AreEqual("supportedManifestInfosForTesting", e.ParamName);
    }
}
