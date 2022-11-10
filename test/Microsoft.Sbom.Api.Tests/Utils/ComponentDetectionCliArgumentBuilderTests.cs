// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using static Microsoft.Sbom.Api.Tests.Utils.ComponentDetectionCliArgumentBuilderTestsExtensions;

namespace Microsoft.Sbom.Api.Tests.Utils
{
    [TestClass]
    public class ComponentDetectionCliArgumentBuilderTests
    {
        public const int DefaultTimeout = 900;

        [TestMethod]
        public void Build_Simple()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                .WithDetectorArgs();

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_Verbosity()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Verbose", "--SourceDirectory", "X:/hello/world")
                .WithDetectorArgs();

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .Verbosity(ComponentDetection.Common.VerbosityMode.Verbose)
                .SourceDirectory("X:/hello/world");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_WithDetectorArgs()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                .WithDetectorArgs("Hello=World,world=hello");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddDetectorArg("Hello", "World")
                .AddDetectorArg("world", "hello");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_WithArgs()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                .WithDetectorArgs()
                .WithArgs("--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_WithArgsDuplicate()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                .WithDetectorArgs()
                .WithArgs("--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_ParseAndAddArgs()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                    .WithDetectorArgs()
                    .WithArgs("--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_ParseAndAddArgsDuplicate()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                .WithDetectorArgs()
                .WithArgs("--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_AddNoValueArgs()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Normal", "--SourceDirectory", "X:/")
                .WithDetectorArgs()
                .WithArgs("--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello", "--Help");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .Verbosity(ComponentDetection.Common.VerbosityMode.Normal)
                .SourceDirectory("X:/")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello")
                .AddArg("Help");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_AddDetectorArgsViaAddArgCombineWithOtherDetectorArgs()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/")
                .WithDetectorArgs("SPDX=hello,Hello=World,world=hello");

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("DetectorArgs", "SPDX=hello")
                .AddDetectorArg("Hello", "World")
                .AddDetectorArg("world", "hello");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Build_WithNullValue()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("ManifestFile", null)
                .AddArg("--DirectoryExclusionList", "X:/hello");

            builder.Build();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Build_WithInvalidArg()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("ManifestFile", "value")
                .AddArg("--", "X:/hello");

            builder.Build();
        }

        [TestMethod]
        public void Build_WithSpacesSourceDirectory()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/path with spaces/")
                .WithDetectorArgs();

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/path with spaces/");

            var result = build.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_WithSpacesInArgument()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/path with spaces/")
                .WithDetectorArgs()
                .WithArgs("--MyArguemnt", "value with spaces");

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/path with spaces/")
                .AddArg("MyArguemnt", "value with spaces");

            var result = build.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_WithSpacesInDetectorArgs()
        {
            var expected = ExpectedArgs("scan", "--Verbosity", "Verbose", "--SourceDirectory", "X:/path with spaces/")
                .WithDetectorArgs("DetectorName=X:/complex/path with spaces");

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .Verbosity(ComponentDetection.Common.VerbosityMode.Verbose)
                .SourceDirectory("X:/path with spaces/")
                .AddDetectorArg("DetectorName", "X:/complex/path with spaces");

            var result = build.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_DetectorArgs_DefaultTimeout()
        {
            var expected = ExpectedArgs()
                .WithDetectorArgs($"Timeout={DefaultTimeout}");

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/");

            var result = build.Build();
            CollectionAssert.AreEquivalent(expected, result[^2..]);
        }

        [TestMethod]
        public void Build_DetectorArgs_Timeout()
        {
            var timeout = 32789;
            var expected = ExpectedArgs().WithDetectorArgs($"Timeout={timeout}");

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddDetectorArg("Timeout", timeout.ToString());

            var result = build.Build();
            CollectionAssert.AreEquivalent(expected, result[^2..]);
        }

        [TestMethod]
        public void Build_MultipleDetectorArgs_Timeout()
        {
            var timeout = 32789;
            var expected = ExpectedArgs().WithDetectorArgs($"Timeout={timeout},Foo=bar");

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddDetectorArg("Foo", "bar")
                .AddDetectorArg("Timeout", timeout.ToString());

            var result = build.Build();
            CollectionAssert.AreEquivalent(expected, result[^2..]);
        }
    }

#pragma warning disable SA1402 // File may only contain a single type
    internal static class ComponentDetectionCliArgumentBuilderTestsExtensions
#pragma warning restore SA1402 // File may only contain a single type
    {
        internal static string[] ExpectedArgs(params string[] args) => args;

        internal static string[] WithArgs(this string[] args, params string[] moreArgs) =>
            Enumerable.Concat(args, moreArgs).ToArray();

        internal static string[] WithDetectorArgs(this string[] args, string detectorArgs = "")
        {
            var defaultTimeoutArg = $"Timeout={ComponentDetectionCliArgumentBuilderTests.DefaultTimeout}";
            if (string.IsNullOrEmpty(detectorArgs))
            {
                detectorArgs = defaultTimeoutArg;
            }
            else if (!detectorArgs.Contains("Timeout="))
            {
                detectorArgs = string.Join(",", defaultTimeoutArg, detectorArgs);
            }

            return args.WithArgs("--DetectorArgs", detectorArgs);
        }
    }
}
