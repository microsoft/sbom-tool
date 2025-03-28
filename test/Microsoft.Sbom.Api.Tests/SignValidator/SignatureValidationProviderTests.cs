// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.SignValidator;

[TestClass]
public class SignatureValidationProviderTests
{
    [TestMethod]
    public void SignatureValidationProvider_AddsValidator_Windows_Succeeds()
    {
        var mockSignatureValidator = new Mock<ISignatureValidator>();
        mockSignatureValidator.SetupGet(s => s.SupportedPlatform).Returns(OSPlatform.Windows);

        var mockOSUtilsWindows = new Mock<IOSUtils>();
        mockOSUtilsWindows.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);

        var signatureValidator = new SignatureValidationProvider(new ISignatureValidator[] { mockSignatureValidator.Object }, mockOSUtilsWindows.Object);
        signatureValidator.Init();
        Assert.IsTrue(signatureValidator.Get().Equals(mockSignatureValidator.Object));

        mockOSUtilsWindows.VerifyAll();
        mockSignatureValidator.VerifyAll();
    }

    [TestMethod]
    public void SignatureValidationProvider_AddsValidator_Linux_Succeeds()
    {
        var mockSignatureValidator = new Mock<ISignatureValidator>();
        mockSignatureValidator.SetupGet(s => s.SupportedPlatform).Returns(OSPlatform.Linux);

        var mockOSUtilsLinux = new Mock<IOSUtils>();
        mockOSUtilsLinux.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Linux);

        var signatureValidator = new SignatureValidationProvider(new ISignatureValidator[] { mockSignatureValidator.Object }, mockOSUtilsLinux.Object);
        signatureValidator.Init();
        Assert.IsTrue(signatureValidator.Get().Equals(mockSignatureValidator.Object));

        mockOSUtilsLinux.VerifyAll();
        mockSignatureValidator.VerifyAll();
    }

    [TestMethod]
    public void SignatureValidationProvider_AddsValidator_Mac_Succeeds()
    {
        var mockSignatureValidator = new Mock<ISignatureValidator>();
        mockSignatureValidator.SetupGet(s => s.SupportedPlatform).Returns(OSPlatform.OSX);

        var mockOSUtilsMac = new Mock<IOSUtils>();
        mockOSUtilsMac.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.OSX);

        var signatureValidator = new SignatureValidationProvider(new ISignatureValidator[] { mockSignatureValidator.Object }, mockOSUtilsMac.Object);
        signatureValidator.Init();
        Assert.IsTrue(signatureValidator.Get().Equals(mockSignatureValidator.Object));

        mockOSUtilsMac.VerifyAll();
        mockSignatureValidator.VerifyAll();
    }

    [TestMethod]
    public void SignatureValidationProvider_NullValidators_Throws()
    {
        var mockOSUtils = new Mock<IOSUtils>();
        mockOSUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);

        Assert.ThrowsException<ArgumentNullException>(() => new SignatureValidationProvider(null, mockOSUtils.Object));
    }
}
