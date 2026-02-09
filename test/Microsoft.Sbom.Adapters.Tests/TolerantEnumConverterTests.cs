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

    /// <summary>
    /// An enum with a -1 member that is NOT named "Unknown",
    /// used to test fallback priority #2 (value -1) independently.
    /// </summary>
    private enum TestEnumWithNegativeOne
    {
        Undefined = -1,
        Alpha = 0,
        Beta = 1
    }

    /// <summary>
    /// An enum that starts at 1 (no 0 value, no -1, no "Unknown"),
    /// used to test fallback priority #4 (first defined value).
    /// </summary>
    private enum TestEnumNoZero
    {
        First = 1,
        Second = 2,
        Third = 3
    }

    private class TestClass
    {
        public TestEnum EnumProperty { get; set; }

        public TestEnum? NullableEnumProperty { get; set; }

        public TestEnumNoUnknown EnumNoUnknownProperty { get; set; }

        public TestEnumWithNegativeOne NegativeOneEnumProperty { get; set; }

        public TestEnumNoZero NoZeroEnumProperty { get; set; }
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

    // -------------------------------------------------------------------
    // CanConvert tests
    // -------------------------------------------------------------------

    [TestMethod]
    public void CanConvert_EnumType_ReturnsTrue()
    {
        var converter = new TolerantEnumConverter();
        Assert.IsTrue(converter.CanConvert(typeof(TestEnum)));
    }

    [TestMethod]
    public void CanConvert_NullableEnumType_ReturnsTrue()
    {
        var converter = new TolerantEnumConverter();
        Assert.IsTrue(converter.CanConvert(typeof(TestEnum?)));
    }

    [TestMethod]
    public void CanConvert_NonEnumType_ReturnsFalse()
    {
        var converter = new TolerantEnumConverter();
        Assert.IsFalse(converter.CanConvert(typeof(string)));
        Assert.IsFalse(converter.CanConvert(typeof(int)));
    }

    // -------------------------------------------------------------------
    // WriteJson tests
    // -------------------------------------------------------------------

    [TestMethod]
    public void SerializeNullEnumValue_WritesNull()
    {
        var obj = new TestClass { NullableEnumProperty = null };
        var json = JsonConvert.SerializeObject(obj, this.settings);

        Assert.IsTrue(json.Contains("null"));
    }

    // -------------------------------------------------------------------
    // GetDefaultEnumValue fallback priority tests
    // -------------------------------------------------------------------

    [TestMethod]
    public void DefaultFallback_EnumWithNegativeOneButNoUnknownName_ReturnsNegativeOne()
    {
        // Tests priority #2: member with value -1 when there is no member named "Unknown"
        var json = @"{ ""NegativeOneEnumProperty"": ""NonExistentValue"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnumWithNegativeOne.Undefined, result.NegativeOneEnumProperty);
    }

    [TestMethod]
    public void DefaultFallback_EnumWithNoZeroNoNegOneNoUnknown_ReturnsFirstDefined()
    {
        // Tests priority #4: first defined value when there is no "Unknown", no -1, and no 0
        var json = @"{ ""NoZeroEnumProperty"": ""NonExistentValue"" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnumNoZero.First, result.NoZeroEnumProperty);
    }

    [TestMethod]
    public void DefaultFallback_EnumNoUnknown_UnknownIntegerValue_ReturnsZero()
    {
        // Tests priority #3: value 0 when there is no "Unknown" name and no -1
        var json = @"{ ""EnumNoUnknownProperty"": 999 }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnumNoUnknown.First, result.EnumNoUnknownProperty);
    }

    // -------------------------------------------------------------------
    // ReadJson edge-case tests
    // -------------------------------------------------------------------

    [TestMethod]
    public void DeserializeNullTokenOnNonNullableEnum_ReturnsDefault()
    {
        // Non-nullable enum receiving a JSON null should fall back to default
        var json = @"{ ""EnumProperty"": null }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.EnumProperty);
    }

    [TestMethod]
    public void DeserializeNullableEnumWithEmptyString_ReturnsNull()
    {
        var json = @"{ ""NullableEnumProperty"": """" }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.IsNull(result.NullableEnumProperty);
    }

    [TestMethod]
    public void DeserializeNullableEnumWithUnknownIntegerValue_ReturnsDefault()
    {
        var json = @"{ ""NullableEnumProperty"": 999 }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.NullableEnumProperty);
    }

    [TestMethod]
    public void DeserializeBooleanTokenForEnum_ReturnsDefault()
    {
        // A boolean JSON token is not a valid enum representation
        var json = @"{ ""EnumProperty"": true }";
        var result = JsonConvert.DeserializeObject<TestClass>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(TestEnum.Unknown, result.EnumProperty);
    }
}
