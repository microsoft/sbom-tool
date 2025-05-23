// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text.Json;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Workflows.Tests;

[TestClass]
public class JsonDocumentCollectionTests
{
    [TestMethod]
    public void JsonDocumentDisposalSucceeds()
    {
        var jsonDoc = JsonDocument.Parse("{\"hello\":\"world\"}");
        var dummySerializer = new Mock<IManifestToolJsonSerializer>().Object;
        var jsonDocumentCollection = new JsonDocumentCollection<IManifestToolJsonSerializer>();
        jsonDocumentCollection.AddJsonDocument(dummySerializer, jsonDoc);

        jsonDocumentCollection.DisposeAllJsonDocuments();

        using var stream = new MemoryStream();
        using var utfJsonWriter = new Utf8JsonWriter(stream);
        Assert.ThrowsException<ObjectDisposedException>(() => jsonDoc.WriteTo(utfJsonWriter));
    }
}
