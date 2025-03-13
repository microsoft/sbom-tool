// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Api.Config.Validators;
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

        var validator = new ManifestInfoValidator(mockAssemblyConfig.Object);
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

        var validator = new ManifestInfoValidator(mockAssemblyConfig.Object);
        validator.ValidateInternal("property", listOfManifestInfos, null);
    }
}
