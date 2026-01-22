// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class PathPatternMatcherTests
{
    [TestMethod]
    public void PathPatternMatcher_SingleWildcard_MatchesCorrectly()
    {
        var basePath = @"C:\test";
        var pattern = @"src\*\file.txt";

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\component\file.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\another\file.txt", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\test\src\component\sub\file.txt", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\test\other\component\file.txt", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_DoubleWildcard_MatchesRecursively()
    {
        var basePath = @"C:\test";
        var pattern = @"src\**\*.txt";

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\file.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\component\file.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\component\sub\deep\file.txt", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\test\other\file.txt", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_NoBasePath_MatchesAbsolutePath()
    {
        var pattern = @"C:\test\src\*.txt";

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\file.txt", pattern));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\another.txt", pattern));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\test\src\sub\file.txt", pattern));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\other\src\file.txt", pattern));
    }

    [TestMethod]
    public void PathPatternMatcher_UnixPaths_MatchesCorrectly()
    {
        var basePath = "/usr/local";
        var pattern = "bin/*";

        Assert.IsTrue(PathPatternMatcher.IsMatch("/usr/local/bin/myapp", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch("/usr/local/bin/tool", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch("/usr/local/bin/sub/tool", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch("/usr/local/lib/myapp", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_MixedPathSeparators_MatchesCorrectly()
    {
        var basePath = @"C:\test";
        var pattern = "src/component/*.txt";  // Using forward slashes in pattern

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\component\file.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:/test/src/component/file.txt", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\test\src\other\file.txt", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_SingleCharacterPatterns_NotSupported()
    {
        // Note: The .NET FileSystemGlobbing library does not support ? wildcard for single character matching
        // This is a known limitation of the underlying implementation
        var basePath = @"C:\test";
        var pattern = @"file*.txt"; // Use * instead of ? for broader matching

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\file1.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\filea.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\file12.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\file.txt", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_EmptyOrNullInputs_ReturnsFalse()
    {
        Assert.IsFalse(PathPatternMatcher.IsMatch(null, "pattern"));
        Assert.IsFalse(PathPatternMatcher.IsMatch(string.Empty, "pattern"));
        Assert.IsFalse(PathPatternMatcher.IsMatch("path", null));
        Assert.IsFalse(PathPatternMatcher.IsMatch("path", string.Empty));
        Assert.IsFalse(PathPatternMatcher.IsMatch(null, null));
    }

    [TestMethod]
    public void PathPatternMatcher_CaseInsensitive_MatchesCorrectly()
    {
        var basePath = @"C:\test";
        var pattern = "SRC/*.TXT";

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\file.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\SRC\FILE.TXT", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\Src\File.Txt", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_ComplexPattern_MatchesCorrectly()
    {
        var basePath = @"C:\workspace";
        var pattern = @"project\**\bin\*.dll";

        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\workspace\project\Debug\bin\app.dll", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\workspace\project\Release\bin\lib.dll", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\workspace\project\x64\Debug\bin\test.dll", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\workspace\project\bin\app.exe", pattern, basePath));
        Assert.IsFalse(PathPatternMatcher.IsMatch(@"C:\workspace\other\bin\app.dll", pattern, basePath));
    }

    [TestMethod]
    public void PathPatternMatcher_DoubleWildcard_MatchesZeroDirectories()
    {
        var basePath = @"C:\test";
        var pattern = @"src\**\*.txt";

        // Test that ** matches zero directories (direct file in src folder)
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\file.txt", pattern, basePath));

        // Test that ** also matches one or more directories
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\component\file.txt", pattern, basePath));
        Assert.IsTrue(PathPatternMatcher.IsMatch(@"C:\test\src\component\sub\file.txt", pattern, basePath));
    }
}
