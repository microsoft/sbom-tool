// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors.Tests
{
    [TestClass]
    public class RelationshipGeneratorTest
    {
        /// <summary>
        /// This repros a channel being orhpaned by not closing it in the face of exceptions
        /// </summary>
        [TestMethod]
        public async Task RunShouldHandleExceptionWithoutOrphaningChannel()
        {
            Mock<IManifestGenerator> mock = new Mock<IManifestGenerator>();

            var m = new ManifestGeneratorProvider(new IManifestGenerator[] { mock.Object });

            var rg = new RelationshipGenerator(m);
            var r = new Relationship() { RelationshipType = RelationshipType.DEPENDS_ON };
            var rs = new List<Relationship> { r };

            var mi = new ManifestInfo();
            mi.Name = "Test";
            mi.Version = "1";
            mock.Setup(m => m.RegisterManifest()).Returns(mi);
            m.Init();

            mock.Setup(m => m.GenerateJsonDocument(It.IsAny<Relationship>())).Throws(new InvalidOperationException());

            ChannelReader<JsonDocument> channel = rg.Run(rs.GetEnumerator(), mi);

            // This timeout will cause an OperationCanceledException to be thrown if the channel is orphaned
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));

            // This will immidately return if the channel is closed.  
            //  If the channel is orphaned this will block until the timeout is reached
            //  which will fail the test.
            await channel.WaitToReadAsync(cts.Token);
        }

        [TestMethod]
        public async Task RunShouldReturnTwoResults()
        {
            Mock<IManifestGenerator> mock = new Mock<IManifestGenerator>();

            var m = new ManifestGeneratorProvider(new IManifestGenerator[] { mock.Object });

            var rg = new RelationshipGenerator(m);
            var r = new Relationship() { RelationshipType = RelationshipType.DEPENDS_ON, SourceElementId = "one", TargetElementId = "two" };
            var r2 = new Relationship() { RelationshipType = RelationshipType.CONTAINS, SourceElementId = "three", TargetElementId = "four" };
            var rs = new List<Relationship> { r, r2 };

            var mi = new ManifestInfo();
            mi.Name = "Test";
            mi.Version = "1";
            mock.Setup(m => m.RegisterManifest()).Returns(mi);
            m.Init();

            var j1 = JsonDocument.Parse(JsonSerializer.Serialize(r));
            var j2 = JsonDocument.Parse(JsonSerializer.Serialize(r2));

            var g1 = new GenerationResult { Document = j1 };
            var g2 = new GenerationResult { Document = j2 };

            mock.Setup(m => m.GenerateJsonDocument(It.Is<Relationship>(r => r.RelationshipType == RelationshipType.DEPENDS_ON))).Returns(g1);
            mock.Setup(m => m.GenerateJsonDocument(It.Is<Relationship>(r => r.RelationshipType == RelationshipType.CONTAINS))).Returns(g2);

            ChannelReader<JsonDocument> channel = rg.Run(rs.GetEnumerator(), mi);

            var docs = new List<JsonDocument>();
            await foreach (JsonDocument jsonDoc in channel.ReadAllAsync())
            {
                docs.Add(jsonDoc);
            }

            Assert.IsTrue(docs.Contains(j1));
            Assert.IsTrue(docs.Contains(j2));
            Assert.IsTrue(docs.Count == 2);
        }


        [TestMethod]
        public async Task RunShouldNotFailWithNull()
        {
            Mock<IManifestGenerator> mock = new Mock<IManifestGenerator>();

            var m = new ManifestGeneratorProvider(new IManifestGenerator[] { mock.Object });

            var rg = new RelationshipGenerator(m);
            var rs = new List<Relationship>();

            var mi = new ManifestInfo();
            mi.Name = "Test";
            mi.Version = "1";
            mock.Setup(m => m.RegisterManifest()).Returns(mi);
            m.Init();

            ChannelReader<JsonDocument> channel = rg.Run(rs.GetEnumerator(), mi);

            var docs = new List<JsonDocument>();
            await foreach (JsonDocument jsonDoc in channel.ReadAllAsync())
            {
                docs.Add(jsonDoc);
            }

            Assert.IsTrue(docs.Count == 0);
        }
    }
}
