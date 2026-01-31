// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace Microsoft.Sbom.Adapters.Tests;

[TestClass]
public class TolerantEnumConverterTests
{
    private readonly JsonSerializerSettings settings = new JsonSerializerSettings
    {
        Converters = { new TolerantEnumConverter() }
    };

    private enum TestEnum
    {
        Unknown = -1,
        Value1 = 0,
        Value2 = 1,
        Value3 = 2
    }

    private enum TestEnumNoUnknown
    {
        First = 0,
        Second = 1,
        Third = 2
    }

    private class TestClass
    {
        public TestEnum EnumProperty { get; set; }

        public TestEnum? NullableEnumProperty { get; set; }

        public TestEnumNoUnknown EnumNoUnknownProperty { get; set; }
    }

    [TestMethod]
    public void DeserializeValidEnumValue_Succeeds()
    {
        var json = @"{ ""EnumProperty"": ""Value1"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Value1, result.EnumProperty);
    }

    [TestMethod]
    public void DeserializeValidEnumValueAsInteger_Succeeds()
    {
        var json = @"{ ""EnumProperty"": 1 }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Value2, result.EnumProperty);
    }

    [TestMethod]
    public void DeserializeUnknownEnumStringValue_ReturnsUnknown()
    {
        var json = @"{ ""EnumProperty"": ""NonExistentValue"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.EnumProperty);
    }

    [TestMethod]
    public void DeserializeUnknownEnumIntegerValue_ReturnsUnknown()
    {
        var json = @"{ ""EnumProperty"": 999 }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.EnumProperty);
    }

    [TestMethod]
    public void DeserializeNullableEnumWithNull_ReturnsNull()
    {
        var json = @"{ ""NullableEnumProperty"": null }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.IsNull(result.NullableEnumProperty);
    }

    [TestMethod]
    public void DeserializeNullableEnumWithValue_Succeeds()
    {
        var json = @"{ ""NullableEnumProperty"": ""Value2"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Value2, result.NullableEnumProperty);
    }

    [TestMethod]
    public void DeserializeNullableEnumWithUnknownValue_ReturnsUnknown()
    {
        var json = @"{ ""NullableEnumProperty"": ""NonExistentValue"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.NullableEnumProperty);
    }

    [TestMethod]
    public void DeserializeEnumWithoutUnknown_UnknownValue_ReturnsFirstValue()
    {
        // For enums without an "Unknown" value, it should return the first defined value
        var json = @"{ ""EnumNoUnknownProperty"": ""NonExistentValue"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnumNoUnknown.First, result.EnumNoUnknownProperty);
    }

    [TestMethod]
    public void DeserializeEnumWithEmptyString_ReturnsUnknown()
    {
        var json = @"{ ""EnumProperty"": """" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.EnumProperty);
    }

    [TestMethod]
    public void SerializeEnumValue_WritesString()
    {
        var obj = new TestClass { EnumProperty = TestEnum.Value2 };
        var json = JsonConvert.SerializeObject(obj, this.settings);

        Assert.IsTrue(json.Contains("\"Value2\""));
    }

    [TestMethod]
    public void DeserializeCaseInsensitive_Succeeds()
    {
        var json = @"{ ""EnumProperty"": ""value1"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Value1, result.EnumProperty);
    }

    [TestMethod]
    public void DeserializeNegativeIntegerForUnknown_ReturnsUnknown()
    {
        var json = @"{ ""EnumProperty"": -1 }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.EnumProperty);
    }
}
