// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class OSUtilsTest
{
    private readonly Mock<ILogger<OSUtils>> logger = new Mock<ILogger<OSUtils>>();

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
        logger.Verify(
            logger => logger.Log(
            It.Is<LogLevel>(logLevel => logLevel == LogLevel.Warning),
            It.Is<EventId>(eventId => eventId.Id == 0),
            It.Is<It.IsAnyType>((@object, @type) => @object.ToString() == $"There are duplicate environment variables in different case for {Variable}, the value used is true" && @type.Name == "FormattedLogValues"),
            It.IsAny<Exception>(),
            It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
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
