﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Moq;
using Serilog;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Tests.Utils
{
    [TestClass]
    public class OSUtilsTest
    {
        private readonly Mock<ILogger> logger = new Mock<ILogger>();

        private readonly Mock<IEnvironmentWrapper> environment = new Mock<IEnvironmentWrapper>();

        private OSUtils osUtils;

        private const string Variable = "Packaging.Variable";

        [TestInitialize]
        public void TestInitialize()
        {
            logger.Reset();
            environment.Reset();
        }

        [TestMethod]
        public void GetEnvironmentVariable_SingleEnvVar()
        {
            IDictionary d = new Dictionary<string, string>()
            {
                { "Agent", "a" },
                { Variable, "true" },
            };

            environment.Setup(o => o.GetEnvironmentVariables()).Returns(d);
            osUtils = new OSUtils(logger.Object, environment.Object);

            Assert.AreEqual("true", osUtils.GetEnvironmentVariable(Variable));
            environment.VerifyAll();
            logger.VerifyAll();
        }

        [TestMethod]
        public void GetEnvironmentVariable_DuplicateEnvVar()
        {
            IDictionary d = new Dictionary<string, string>()
            {
                { "Agent", "a" },
                { Variable, "true" },
                { Variable.ToLower(), "trueLower" },
                { Variable.ToUpper(), "trueUpper" },
            };

            environment.Setup(o => o.GetEnvironmentVariables()).Returns(d);
            osUtils = new OSUtils(logger.Object, environment.Object);

            Assert.AreEqual("true", osUtils.GetEnvironmentVariable(Variable));
            environment.VerifyAll();
            logger.Verify(o => o.Warning($"There are duplicate environment variables in different case for {Variable}, the value used is true"), Times.Once());
        }

        [TestMethod]
        public void GetEnvironmentVariable_Null()
        {
            IDictionary d = new Dictionary<string, string>()
            {
                { "Agent", "a" },
            };

            environment.Setup(o => o.GetEnvironmentVariables()).Returns(d);
            osUtils = new OSUtils(logger.Object, environment.Object);

            Assert.AreEqual(null, osUtils.GetEnvironmentVariable(Variable));
            environment.VerifyAll();
            logger.VerifyAll();
        }

        [TestMethod]
        public void GetEnvironmentVariable_NullFromEmptyEnvVar()
        {
            IDictionary d = new Dictionary<string, string>() { };

            environment.Setup(o => o.GetEnvironmentVariables()).Returns(d);
            osUtils = new OSUtils(logger.Object, environment.Object);

            Assert.AreEqual(null, osUtils.GetEnvironmentVariable(Variable));
            environment.VerifyAll();
            logger.VerifyAll();
        }
    }
}
