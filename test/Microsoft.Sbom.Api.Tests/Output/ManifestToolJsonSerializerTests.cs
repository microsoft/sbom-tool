// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Output.Tests;

[TestClass]
public class ManifestToolJsonSerializerTests
{
    private readonly string metadataString = "{\"header\":\"value\"}";

    [TestMethod]
    public void ManifestToolJsonSerializerTest_HappyPath_Succeeds()
    {
        var jsonDoc = JsonDocument.Parse("{\"hello\":\"world\"}");

        string result = null;

        using (var stream = new MemoryStream())
        {
            using (var serializer = new ManifestToolJsonSerializer(stream))
            {
                serializer.StartJsonObject();
                serializer.StartJsonArray("Outputs");
                serializer.Write(jsonDoc);
                serializer.EndJsonArray();
                serializer.WriteJsonString(metadataString);
                serializer.FinalizeJsonObject();
            }

            result = Encoding.UTF8.GetString(stream.ToArray());
        }

        var expected = JsonSerializer.Serialize(JsonDocument.Parse("{\"Outputs\":[{\"hello\":\"world\"}],\"header\":\"value\"}"), new JsonSerializerOptions { WriteIndented = true });
        Assert.AreEqual(expected, result);

        using var stream2 = new MemoryStream();
        using var utfJsonWriter = new Utf8JsonWriter(stream2);
        try
        {
            jsonDoc.WriteTo(utfJsonWriter);
            Assert.Fail("Json document was not disposed by the serializer");
        }
        catch (Exception e)
        {
            Assert.AreEqual(typeof(ObjectDisposedException), e.GetType());
        }
    }

    [TestMethod]
    public void ManifestToolJsonSerializerTest_HeaderWithoutArrayStart_Succeeds()
    {
        var jsonDoc = JsonDocument.Parse("{\"hello\":\"world\"}");

        string result = null;

        using (var stream = new MemoryStream())
        {
            using (var serializer = new ManifestToolJsonSerializer(stream))
            {
                serializer.StartJsonObject();
                serializer.StartJsonArray("Outputs");
                serializer.Write(jsonDoc);
                serializer.EndJsonArray();
                serializer.WriteJsonString(metadataString);
                serializer.FinalizeJsonObject();
            }

            result = Encoding.UTF8.GetString(stream.ToArray());
        }

        var expected = JsonSerializer.Serialize(JsonDocument.Parse("{\"Outputs\":[{\"hello\":\"world\"}],\"header\":\"value\"}"), new JsonSerializerOptions { WriteIndented = true });
        Assert.AreEqual(expected, result);

        using var stream2 = new MemoryStream();
        using var utfJsonWriter = new Utf8JsonWriter(stream2);
        try
        {
            jsonDoc.WriteTo(utfJsonWriter);
            Assert.Fail("Json document was not disposed by the serializer");
        }
        catch (Exception e)
        {
            Assert.AreEqual(typeof(ObjectDisposedException), e.GetType());
        }
    }

    [TestMethod]
    [ExpectedException(typeof(ObjectDisposedException))]
    public void ManifestToolJsonSerializerTest_WriteDisposedJsonDocument_Fails()
    {
        var jsonDoc = JsonDocument.Parse("{\"hello\":\"world\"}");

        using var stream = new MemoryStream();
        using var serializer = new ManifestToolJsonSerializer(stream);

        jsonDoc.Dispose();

        serializer.StartJsonObject();
        serializer.WriteJsonString(metadataString);
        serializer.Write(jsonDoc);
        serializer.FinalizeJsonObject();
    }
}
