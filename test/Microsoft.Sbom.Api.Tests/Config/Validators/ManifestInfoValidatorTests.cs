// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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

    [TestMethod]
    public void InvalidManifestInfoThrows()
    {
        var invalidManifestInfo = new ManifestInfo
        {
            Name = "SPDX",
            Version = "asdf"
        };

        var validator = new ManifestInfoValidator(mockAssemblyConfig.Object);
        Assert.ThrowsException<ValidationArgException>(() => validator.ValidateInternal("property", invalidManifestInfo, null));
    }

    [DataRow("2.2")]
    [DataRow("3.0")]
    [TestMethod]
    public void ValidManifestInfoPasses(string spdxVersion)
    {
        var validManifestInfo = new ManifestInfo
        {
            Name = "SPDX",
            Version = spdxVersion
        };

        var validator = new ManifestInfoValidator(mockAssemblyConfig.Object);
        validator.ValidateInternal("property", validManifestInfo, null);
    }
}
