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
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_Verbosity()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .Verbosity(ComponentDetection.Common.VerbosityMode.Verbose)
                .SourceDirectory("X:/hello/world");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Verbose --SourceDirectory X:/hello/world", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_WithDetectorArgs()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddDetectorArg("Hello", "World")
                .AddDetectorArg("world", "hello");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/ --DetectorArgs Hello=World,world=hello", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_WithArgs()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/ --ManifestFile Hello --DirectoryExclusionList X:/hello", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_WithArgsDuplicate()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/ --ManifestFile Hello --DirectoryExclusionList X:/hello", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_ParseAndAddArgs()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/ --ManifestFile Hello --DirectoryExclusionList X:/hello", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_ParseAndAddArgsDuplicate()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello")
                .AddArg("ManifestFile", "Hello")
                .AddArg("--DirectoryExclusionList", "X:/hello");


            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/ --ManifestFile Hello --DirectoryExclusionList X:/hello", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_AddNoValueArgs()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .Verbosity(ComponentDetection.Common.VerbosityMode.Normal)
                .SourceDirectory("X:/")
                .ParseAndAddArgs("--ManifestFile Hello --DirectoryExclusionList X:/hello")
                .AddArg("Help");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Normal --SourceDirectory X:/ --ManifestFile Hello --DirectoryExclusionList X:/hello --Help", string.Join(" ", result));
        }

        [TestMethod]
        public void Build_AddDetectorArgsWeirdWay()
        {
            var builder = new ComponentDetectionCliArgumentBuilder()
                .Scan()
                .SourceDirectory("X:/")
                .AddArg("DetectorArgs", "SPDX=hello")
                .AddDetectorArg("Hello", "World")
                .AddDetectorArg("world", "hello");

            var result = builder.Build();
            Assert.AreEqual("scan --Verbosity Quiet --SourceDirectory X:/ --DetectorArgs SPDX=hello,Hello=World,world=hello", string.Join(" ", result));
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
    }
}
