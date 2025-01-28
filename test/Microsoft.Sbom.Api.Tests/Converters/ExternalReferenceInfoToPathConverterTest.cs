// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Serilog;

namespace Microsoft.Sbom.Api.Tests.Converters;

[TestClass]
public class ExternalReferenceInfoToPathConverterTest
{
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();

    [TestMethod]
    public async Task When_ConvertingExternalDocRefInfoToPath_WithCommonCase_ThenTestPass()
    {
        var externalDocRef1 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path1"
        };
        var externalDocRef2 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path2"
        };
        var externalDocRef3 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path3"
        };
        var externalDocRef4 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path4"
        };

        var externalDocRefs = new List<ExternalDocumentReferenceInfo>()
        {
            externalDocRef1, externalDocRef2, externalDocRef3, externalDocRef4
        };

        var externalDocRefChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
        foreach (var externalDocRef in externalDocRefs)
        {
            await externalDocRefChannel.Writer.WriteAsync(externalDocRef);
        }

        externalDocRefChannel.Writer.Complete();

        var converter = new ExternalReferenceInfoToPathConverter(mockLogger.Object);
        var (results, errors) = converter.Convert(externalDocRefChannel);

        var paths = await results.ReadAllAsync().ToListAsync();

        await foreach (var error in errors.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.ErrorType}");
        }

        var count = 1;
        await foreach (var path in results.ReadAllAsync())
        {
            Assert.Equals($"path{count}", path);
            count++;
        }

        Assert.AreEqual(externalDocRefs.Count, paths.Count);
    }

    [TestMethod]
    public async Task When_ConvertingExternalDocRefInfoToPath_WithMissingPath_ThenTestPass()
    {
        var externalDocRef1 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path1"
        };
        var externalDocRef2 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path2"
        };
        var externalDocRef3 = new ExternalDocumentReferenceInfo()
        {
            Path = @"/path3"
        };
        var externalDocRef4 = new ExternalDocumentReferenceInfo() { };

        var externalDocRefs = new List<ExternalDocumentReferenceInfo>()
        {
            externalDocRef1, externalDocRef2, externalDocRef3, externalDocRef4
        };

        var externalDocRefChannel = Channel.CreateUnbounded<ExternalDocumentReferenceInfo>();
        foreach (var externalDocRef in externalDocRefs)
        {
            await externalDocRefChannel.Writer.WriteAsync(externalDocRef);
        }

        externalDocRefChannel.Writer.Complete();

        var converter = new ExternalReferenceInfoToPathConverter(mockLogger.Object);
        var (results, errors) = converter.Convert(externalDocRefChannel);

        var paths = await results.ReadAllAsync().ToListAsync();
        var errorList = await errors.ReadAllAsync().ToListAsync();

        await foreach (var error in errors.ReadAllAsync())
        {
            Assert.Fail($"Caught exception: {error.ErrorType}");
        }

        Assert.AreEqual(3, paths.Count);
        Assert.AreEqual(1, errorList.Count);
    }
}
