// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.Utils;

[TestClass]
public class ExternalReferenceDeduplicatorTests
{
    private readonly ChannelUtils channelUtils = new ChannelUtils();

    [TestMethod]
    public async Task When_DeduplicatingExternalDocRefInfo_WithSingleChannel_ThenTestPass()
    {
        var references = new List<ExternalDocumentReferenceInfo>()
        {
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/1"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/2"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/2"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/3"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/4"
            },
        };

        var inputChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();

        foreach (var reference in references)
        {
            await inputChannel.Writer.WriteAsync(reference);
        }

        inputChannel.Writer.Complete();

        var deduplicator = new ExternalReferenceDeduplicator();
        var output = deduplicator.Deduplicate(inputChannel);

        var results = await output.ReadAllAsync().ToListAsync();

        Assert.AreEqual(results.Count, references.Count - 1);
    }

    [TestMethod]
    public async Task When_DeduplicatingExternalDocRefInfo_WithConcurrentChannel_ThenTestPass()
    {
        var references = new List<ExternalDocumentReferenceInfo>()
        {
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/1"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/2"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/2"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/3"
            },
            new ExternalDocumentReferenceInfo()
            {
                DocumentNamespace = "http://sbom.test/4"
            },
        };

        var deduplicator = new ExternalReferenceDeduplicator();

        var task1 = Task.Run(async () =>
        {
            var inputChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();

            foreach (var reference in references)
            {
                await inputChannel.Writer.WriteAsync(reference);
            }

            inputChannel.Writer.Complete();

            var output = deduplicator.Deduplicate(inputChannel);

            return output;
        });

        var task2 = Task.Run(async () =>
        {
            var inputChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();

            foreach (var reference in references)
            {
                await inputChannel.Writer.WriteAsync(reference);
            }

            inputChannel.Writer.Complete();

            var output = deduplicator.Deduplicate(inputChannel);

            return output;
        });

        await Task.WhenAll(task1, task2);
        var result = channelUtils.Merge(new ChannelReader<ExternalDocumentReferenceInfo>[] { task1.Result, task2.Result });
        var resultList = await result.ReadAllAsync().ToListAsync();

        Assert.AreEqual(resultList.Count, references.Count - 1);
    }

    [TestMethod]
    public void When_GetKeyForExternalDocRef_ThenTestPass()
    {
        var deduplicator = new ExternalReferenceDeduplicator();

        Assert.AreEqual("http://sbom.test/1", deduplicator.GetKey(new ExternalDocumentReferenceInfo() { DocumentNamespace = "http://sbom.test/1" }));
        Assert.AreEqual(null, deduplicator.GetKey(null));
    }
}