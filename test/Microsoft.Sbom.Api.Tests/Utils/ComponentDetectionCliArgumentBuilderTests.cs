// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Microsoft.Sbom.Api.Tests.Utils
{
    [TestClass]
    public class ComponentDetectionCliArgumentBuilderTests
    {
        [TestMethod]
        public void Build_Simple()
        {
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/" };

            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/");

            var result = builder.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_Verbosity()
        {
            var expected = new string[] { "scan", "--Verbosity", "Verbose", "--SourceDirectory", "X:/hello/world" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/", "--DetectorArgs", "Hello=World,world=hello" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/", "--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/", "--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/", "--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/", "--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello" };

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
            var expected = new string[] { "scan", "--Verbosity", "Normal", "--SourceDirectory", "X:/", "--ManifestFile", "Hello", "--DirectoryExclusionList", "X:/hello", "--Help" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/", "--DetectorArgs", "SPDX=hello,Hello=World,world=hello" };

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
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/path with spaces/" };

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/path with spaces/");
            
            var result = build.Build();
            CollectionAssert.AreEqual(expected, result);
        }

        [TestMethod]
        public void Build_WithSpacesInArgument()
        {
            var expected = new string[] { "scan", "--Verbosity", "Quiet", "--SourceDirectory", "X:/path with spaces/", "--MyArguemnt", "value with spaces" };

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
            var expected = new string[] { "scan", "--Verbosity", "Verbose", "--SourceDirectory", "X:/path with spaces/", "--DetectorArgs", "DetectorName=X:/complex/path with spaces" };

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
            var expected = new string[] { "--DetectorArgs", "Timeout=900" };

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
            var expected = new string[] { "--DetectorArgs", $"Timeout={timeout}" };

            var build = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddDetectorArg("Timeout", timeout.ToString());

            var result = build.Build();
            CollectionAssert.AreEquivalent(expected, result[^2..]);
        }
    }
}
