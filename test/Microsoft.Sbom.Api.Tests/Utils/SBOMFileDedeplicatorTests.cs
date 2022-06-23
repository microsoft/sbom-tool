﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Tests.Utils
{
    [TestClass]
    public class SBOMFileDedeplicatorTests
    {
        private readonly ChannelUtils channelUtils = new ChannelUtils();

        [TestMethod]
        public async Task When_DeduplicatingSBOMFile_WithSingleChannel_ThenTestPass()
        {
            var sbomFiles = new List<InternalSBOMFileInfo>()
            {
                new InternalSBOMFileInfo()
                {
                    Path = "./file1.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file2.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file2.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file3.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file4.txt"
                }
            };

            var inputChannel = Channel.CreateUnbounded<InternalSBOMFileInfo>();

            foreach (var sbomFile in sbomFiles)
            {
                await inputChannel.Writer.WriteAsync(sbomFile);
            }

            inputChannel.Writer.Complete();

            var deduplicator = new InternalSBOMFileInfoDeduplicator();
            var output = deduplicator.Deduplicate(inputChannel);

            var results = await output.ReadAllAsync().ToListAsync();

            Assert.AreEqual(results.Count, sbomFiles.Count - 1);
        }

        [TestMethod]
        public async Task When_DeduplicatingSBOMFile_WithConcurrentChannel_ThenTestPass()
        {
            var sbomFiles = new List<InternalSBOMFileInfo>()
            {
                new InternalSBOMFileInfo()
                {
                    Path = "./file1.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file2.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file2.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file3.txt"
                },
                new InternalSBOMFileInfo()
                {
                    Path = "./file4.txt"
                }
            };

            var deduplicator = new InternalSBOMFileInfoDeduplicator();

            var task1 = Task.Run(async () =>
            {
                var inputChannel = Channel.CreateUnbounded<InternalSBOMFileInfo>();

                foreach (var fileInfo in sbomFiles)
                {
                    await inputChannel.Writer.WriteAsync(fileInfo);
                }

                inputChannel.Writer.Complete();

                var output = deduplicator.Deduplicate(inputChannel);

                return output;
            });

            var task2 = Task.Run(async () =>
            {
                var inputChannel = Channel.CreateUnbounded<InternalSBOMFileInfo>();

                foreach (var fileInfo in sbomFiles)
                {
                    await inputChannel.Writer.WriteAsync(fileInfo);
                }

                inputChannel.Writer.Complete();

                var output = deduplicator.Deduplicate(inputChannel);

                return output;
            });

            await Task.WhenAll(task1, task2);
            var result = channelUtils.Merge(new ChannelReader<InternalSBOMFileInfo>[] { task1.Result, task2.Result });
            var resultList = await result.ReadAllAsync().ToListAsync();

            Assert.AreEqual(resultList.Count, sbomFiles.Count - 1);
        }

        [TestMethod]
        public void When_GetKeyForSBOMFile_ThenTestPass()
        {
            var deduplicator = new InternalSBOMFileInfoDeduplicator();

            Assert.AreEqual("./file1.txt", deduplicator.GetKey(new InternalSBOMFileInfo() { Path = "./file1.txt" }));
            Assert.AreEqual(null, deduplicator.GetKey(null));
        }
    }
}
