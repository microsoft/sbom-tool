// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Filters.Tests;

[TestClass]
public class DownloadedRootPathFilterTests
{
    private readonly Mock<ILogger> logger = new Mock<ILogger>();

    [TestMethod]
    public void DownloadedRootPathFilterTest_NoFilterPath_Succeeds()
    {
        var fileSystemMock = new Mock<IFileSystemUtils>();

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.RootPathFilter).Returns((ConfigurationSetting<string>)null);
        configMock.SetupGet(c => c.RootPathPatterns).Returns((ConfigurationSetting<string>)null);

        var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
        filter.Init();

        Assert.IsTrue(filter.IsValid("hello"));
        Assert.IsTrue(filter.IsValid(null));
        Assert.IsTrue(filter.IsValid("c:/test"));
        fileSystemMock.VerifyAll();
        configMock.VerifyAll();
    }

    [TestMethod]
    public void DownloadedRootPathFilterTest_FilterPath_Succeeds()
    {
        var fileSystemMock = new Mock<IFileSystemUtils>();
        fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>())).Returns((string r, string p) => $"{r}/{p}");

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "C:/test" });
        configMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "validPath" });
        configMock.SetupGet(c => c.RootPathPatterns).Returns((ConfigurationSetting<string>)null);

        var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
        filter.Init();

        Assert.IsTrue(filter.IsValid("c:/test/validPath/test"));
        Assert.IsTrue(filter.IsValid("c:/test/validPath"));
        Assert.IsTrue(filter.IsValid("c:/test/validPath/test/me"));
        Assert.IsFalse(filter.IsValid(null));
        Assert.IsFalse(filter.IsValid("c:/test/InvalidPath"));
        Assert.IsFalse(filter.IsValid("c:/test/InvalidPath/f"));

        fileSystemMock.VerifyAll();
        configMock.VerifyAll();
    }

    [TestMethod]
    public void DownloadedRootPathFilterTest_PatternFiltering_Succeeds()
    {
        var fileSystemMock = new Mock<IFileSystemUtils>();

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "C:/test" });
        configMock.SetupGet(c => c.RootPathPatterns).Returns(new ConfigurationSetting<string> { Value = "src/**/*.cs;bin/*.dll" });

        var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
        filter.Init();

        // Should match pattern src/**/*.cs
        Assert.IsTrue(filter.IsValid("C:/test/src/component/file.cs"));
        Assert.IsTrue(filter.IsValid("C:/test/src/deep/nested/component/file.cs"));

        // Should match pattern bin/*.dll
        Assert.IsTrue(filter.IsValid("C:/test/bin/app.dll"));

        // Should not match patterns
        Assert.IsFalse(filter.IsValid("C:/test/lib/component.dll"));
        Assert.IsFalse(filter.IsValid("C:/test/src/component/file.txt"));
        Assert.IsFalse(filter.IsValid("C:/test/bin/nested/app.dll"));
        Assert.IsFalse(filter.IsValid(null));

        fileSystemMock.VerifyAll();
        configMock.VerifyAll();
    }

    [TestMethod]
    public void DownloadedRootPathFilterTest_PatternTakesPrecedence_Succeeds()
    {
        var fileSystemMock = new Mock<IFileSystemUtils>();
        fileSystemMock.Setup(f => f.JoinPaths(It.IsAny<string>(), It.IsAny<string>()))
                     .Returns((string path1, string path2) => Path.Combine(path1, path2));

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.BuildDropPath).Returns(new ConfigurationSetting<string> { Value = "C:/test" });
        configMock.SetupGet(c => c.RootPathFilter).Returns(new ConfigurationSetting<string> { Value = "oldPath" });
        configMock.SetupGet(c => c.RootPathPatterns).Returns(new ConfigurationSetting<string> { Value = "src/*.cs" });

        var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
        filter.Init();

        // Should use pattern matching, not legacy path filtering
        Assert.IsTrue(filter.IsValid("C:/test/src/file.cs"));
        Assert.IsFalse(filter.IsValid("C:/test/oldPath/file.txt")); // This would match with RootPathFilter but should be ignored
        Assert.IsFalse(filter.IsValid("C:/test/src/nested/file.cs")); // Doesn't match the pattern

        fileSystemMock.VerifyAll();
        configMock.VerifyAll();
    }

    [TestMethod]
    public void DownloadedRootPathFilterTest_EmptyPattern_SkipsValidation()
    {
        var fileSystemMock = new Mock<IFileSystemUtils>();

        var configMock = new Mock<IConfiguration>();
        configMock.SetupGet(c => c.RootPathPatterns).Returns(new ConfigurationSetting<string> { Value = "   ;  ; " }); // Only whitespace and separators

        var filter = new DownloadedRootPathFilter(configMock.Object, fileSystemMock.Object, logger.Object);
        filter.Init();

        // Should skip validation since patterns contain only whitespace and separators
        Assert.IsTrue(filter.IsValid("any/path/should/pass"));
        Assert.IsTrue(filter.IsValid(null));

        fileSystemMock.VerifyAll();
        configMock.VerifyAll();
    }
}
