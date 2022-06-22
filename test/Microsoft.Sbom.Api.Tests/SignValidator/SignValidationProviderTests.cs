// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;
using System;
using System.Runtime.InteropServices;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.SignValidator.Tests
{
    [TestClass]
    public class SignValidationProviderTests
    {
        IMock<ILogger> mockLogger;

        [TestInitialize]
        public void Setup()
        {
            mockLogger = new Mock<ILogger>();
        }

        [TestMethod]
        public void SignValidationProvider_AddsValidator_Succeeds()
        {
            var mockSignValidator = new Mock<ISignValidator>();
            mockSignValidator.SetupGet(s => s.SupportedPlatform).Returns(OSPlatform.Windows);

            var mockOSUtils = new Mock<IOSUtils>();
            mockOSUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);

            var signValidator = new SignValidationProvider(new ISignValidator[] { mockSignValidator.Object }, mockLogger.Object, mockOSUtils.Object);
            signValidator.Init();
            Assert.IsTrue(signValidator.Get().Equals(mockSignValidator.Object));

            mockOSUtils.VerifyAll();
            mockSignValidator.VerifyAll();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SignValidationProvider_NullValidators_Throws()
        {
            var mockOSUtils = new Mock<IOSUtils>();
            mockOSUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Windows);

            var signValidator = new SignValidationProvider(null, mockLogger.Object, mockOSUtils.Object);
            signValidator.Init();
            signValidator.Get();
        }

        [TestMethod]
        [ExpectedException(typeof(SignValidatorNotFoundException))]
        public void SignValidationProvider_NotFoundValidators_Throws()
        {
            var mockSignValidator = new Mock<ISignValidator>();
            mockSignValidator.SetupGet(s => s.SupportedPlatform).Returns(OSPlatform.Windows);

            var mockOSUtils = new Mock<IOSUtils>();
            mockOSUtils.Setup(o => o.GetCurrentOSPlatform()).Returns(OSPlatform.Linux);

            var signValidator = new SignValidationProvider(new ISignValidator[] { mockSignValidator.Object }, mockLogger.Object, mockOSUtils.Object);
            signValidator.Init();
            signValidator.Get();
        }
    }
}