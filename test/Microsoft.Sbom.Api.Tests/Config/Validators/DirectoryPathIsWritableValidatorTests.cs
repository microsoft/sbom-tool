// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Config.Validators;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PowerArgs;

namespace Microsoft.Sbom.Api.Tests.Config.Validators;

[TestClass]
public class DirectoryPathIsWritableValidatorTests
{
    private readonly Mock<IAssemblyConfig> mockAssemblyConfig = new Mock<IAssemblyConfig>();

    [TestMethod]
    [ExpectedException(typeof(ValidationArgException))]
    public void WhenDirectoryDoesNotExistsThrows()
    {
        var fileSystemUtilsMock = new Mock<IFileSystemUtils>();
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(false).Verifiable();

        var validator = new DirectoryPathIsWritableValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object);
        validator.ValidateInternal("property", "value", null);
    }

    [TestMethod]
    [ExpectedException(typeof(AccessDeniedValidationArgException))]
    public void WhenDirectoryDoesNotHaveWriteAccessThrows()
    {
        var fileSystemUtilsMock = new Mock<IFileSystemUtils>();
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(false).Verifiable();

        var validator = new DirectoryPathIsWritableValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object);
        validator.ValidateInternal("property", "value", null);
    }

    [TestMethod]
    public void WhenDirectoryHasWriteAccess()
    {
        var fileSystemUtilsMock = new Mock<IFileSystemUtils>();
        fileSystemUtilsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true).Verifiable();
        fileSystemUtilsMock.Setup(f => f.DirectoryHasWritePermissions(It.IsAny<string>())).Returns(true).Verifiable();

        var validator = new DirectoryPathIsWritableValidator(fileSystemUtilsMock.Object, mockAssemblyConfig.Object);
        validator.ValidateInternal("property", "value", null);
    }
}
