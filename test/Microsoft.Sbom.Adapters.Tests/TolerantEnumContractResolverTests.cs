// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Microsoft.Sbom.Adapters.Tests;

[TestClass]
public class TolerantEnumContractResolverTests
{
    private readonly JsonSerializerSettings settings = new JsonSerializerSettings
    {
        ContractResolver = new TolerantEnumContractResolver(),
        Converters = { new TolerantEnumConverter() }
    };

    private enum TestEnum
    {
        Unknown = -1,
        Value1 = 0,
        Value2 = 1,
        Value3 = 2
    }

    private class ClassWithEnumArray
    {
        public TestEnum[] EnumArray { get; set; } = System.Array.Empty<TestEnum>();
    }

    private class ClassWithEnumList
    {
        public List<TestEnum> EnumList { get; set; } = new List<TestEnum>();
    }

    private class ClassWithEnumIEnumerable
    {
        public IEnumerable<TestEnum> EnumEnumerable { get; set; } = Enumerable.Empty<TestEnum>();
    }

    private class ClassWithMixedProperties
    {
        public string Name { get; set; } = string.Empty;

        public TestEnum SingleEnum { get; set; }

        public TestEnum? NullableEnum { get; set; }

        public List<TestEnum> EnumList { get; set; } = new List<TestEnum>();

        public int[] IntArray { get; set; } = System.Array.Empty<int>();
    }

    /// <summary>
    /// Mimics the upstream Detector.SupportedComponentTypes which has
    /// [JsonProperty(ItemConverterType = typeof(StringEnumConverter))].
    /// </summary>
    private class ClassWithItemConverterAttribute
    {
        [JsonProperty(ItemConverterType = typeof(StringEnumConverter))]
        public IEnumerable<TestEnum> EnumValues { get; set; } = Enumerable.Empty<TestEnum>();
    }

    /// <summary>
    /// Tests that a concrete collection type (List) with ItemConverterType attribute
    /// is also handled. Unlike IEnumerable, List implements IEnumerable via GetInterfaces().
    /// </summary>
    private class ClassWithListAndItemConverterAttribute
    {
        [JsonProperty(ItemConverterType = typeof(StringEnumConverter))]
        public List<TestEnum> EnumValues { get; set; } = new List<TestEnum>();
    }

    [TestMethod]
    public void DeserializeEnumArray_WithValidValues_Succeeds()
    {
        var json = @"{ ""EnumArray"": [""Value1"", ""Value2"", ""Value3""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumArray.Length);
        Assert.AreEqual(TestEnum.Value1, result.EnumArray[0]);
        Assert.AreEqual(TestEnum.Value2, result.EnumArray[1]);
        Assert.AreEqual(TestEnum.Value3, result.EnumArray[2]);
    }

    [TestMethod]
    public void DeserializeEnumArray_WithUnknownValues_ReturnsUnknownForInvalid()
    {
        var json = @"{ ""EnumArray"": [""Value1"", ""InvalidValue"", ""Value3""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumArray.Length);
        Assert.AreEqual(TestEnum.Value1, result.EnumArray[0]);
        Assert.AreEqual(TestEnum.Unknown, result.EnumArray[1]);
        Assert.AreEqual(TestEnum.Value3, result.EnumArray[2]);
    }

    [TestMethod]
    public void DeserializeEnumArray_WithAllUnknownValues_ReturnsAllUnknown()
    {
        var json = @"{ ""EnumArray"": [""Foo"", ""Bar"", ""Baz""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumArray.Length);
        Assert.IsTrue(result.EnumArray.All(e => e == TestEnum.Unknown));
    }

    [TestMethod]
    public void DeserializeEnumArray_WithIntegerValues_Succeeds()
    {
        var json = @"{ ""EnumArray"": [0, 1, 999] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumArray.Length);
        Assert.AreEqual(TestEnum.Value1, result.EnumArray[0]);
        Assert.AreEqual(TestEnum.Value2, result.EnumArray[1]);
        Assert.AreEqual(TestEnum.Unknown, result.EnumArray[2]); // 999 is unknown
    }

    [TestMethod]
    public void DeserializeEnumList_WithValidValues_Succeeds()
    {
        var json = @"{ ""EnumList"": [""Value1"", ""Value2""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumList>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(2, result.EnumList.Count);
        Assert.AreEqual(TestEnum.Value1, result.EnumList[0]);
        Assert.AreEqual(TestEnum.Value2, result.EnumList[1]);
    }

    [TestMethod]
    public void DeserializeEnumList_WithUnknownValues_ReturnsUnknownForInvalid()
    {
        var json = @"{ ""EnumList"": [""Value1"", ""SomeNewValue"", ""AnotherNewValue""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumList>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumList.Count);
        Assert.AreEqual(TestEnum.Value1, result.EnumList[0]);
        Assert.AreEqual(TestEnum.Unknown, result.EnumList[1]);
        Assert.AreEqual(TestEnum.Unknown, result.EnumList[2]);
    }

    [TestMethod]
    public void DeserializeEnumIEnumerable_WithUnknownValues_ReturnsUnknownForInvalid()
    {
        var json = @"{ ""EnumEnumerable"": [""Value1"", ""NewFutureValue""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumIEnumerable>(json, this.settings);

        Assert.IsNotNull(result);
        var list = result.EnumEnumerable.ToList();
        Assert.AreEqual(2, list.Count);
        Assert.AreEqual(TestEnum.Value1, list[0]);
        Assert.AreEqual(TestEnum.Unknown, list[1]);
    }

    [TestMethod]
    public void DeserializeMixedProperties_WithUnknownEnumValues_Succeeds()
    {
        var json = @"{
            ""Name"": ""TestName"",
            ""SingleEnum"": ""UnknownSingleValue"",
            ""NullableEnum"": ""UnknownNullableValue"",
            ""EnumList"": [""Value1"", ""UnknownListValue"", ""Value2""],
            ""IntArray"": [1, 2, 3]
        }";
        var result = JsonConvert.DeserializeObject<ClassWithMixedProperties>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual("TestName", result.Name);
        Assert.AreEqual(TestEnum.Unknown, result.SingleEnum);
        Assert.AreEqual(TestEnum.Unknown, result.NullableEnum);
        Assert.AreEqual(3, result.EnumList.Count);
        Assert.AreEqual(TestEnum.Value1, result.EnumList[0]);
        Assert.AreEqual(TestEnum.Unknown, result.EnumList[1]);
        Assert.AreEqual(TestEnum.Value2, result.EnumList[2]);
        CollectionAssert.AreEqual(new[] { 1, 2, 3 }, result.IntArray);
    }

    [TestMethod]
    public void DeserializeEmptyEnumArray_Succeeds()
    {
        var json = @"{ ""EnumArray"": [] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(0, result.EnumArray.Length);
    }

    [TestMethod]
    public void DeserializeNullEnumArray_Succeeds()
    {
        var json = @"{ ""EnumArray"": null }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.IsNull(result.EnumArray);
    }

    [TestMethod]
    public void SerializeEnumArray_WritesCorrectValues()
    {
        var obj = new ClassWithEnumArray
        {
            EnumArray = new[] { TestEnum.Value1, TestEnum.Unknown, TestEnum.Value3 }
        };
        var json = JsonConvert.SerializeObject(obj, this.settings);

        Assert.IsTrue(json.Contains("\"Value1\""));
        Assert.IsTrue(json.Contains("\"Unknown\""));
        Assert.IsTrue(json.Contains("\"Value3\""));
    }

    [TestMethod]
    public void DeserializeEnumArray_CaseInsensitive_Succeeds()
    {
        var json = @"{ ""EnumArray"": [""value1"", ""VALUE2"", ""VaLuE3""] }";
        var result = JsonConvert.DeserializeObject<ClassWithEnumArray>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumArray.Length);
        Assert.AreEqual(TestEnum.Value1, result.EnumArray[0]);
        Assert.AreEqual(TestEnum.Value2, result.EnumArray[1]);
        Assert.AreEqual(TestEnum.Value3, result.EnumArray[2]);
    }

    [TestMethod]
    public void DeserializeEnumCollection_WithItemConverterAttribute_UnknownValues_UsesTolerantConverter()
    {
        // This is the key test: it mimics the upstream Detector.SupportedComponentTypes which has
        // [JsonProperty(ItemConverterType = typeof(StringEnumConverter))] on it.
        // Our TolerantEnumContractResolver should override this attribute-level converter.
        var json = @"{ ""EnumValues"": [""Value1"", ""UnknownEnum"", ""AnotherUnknown""] }";
        var result = JsonConvert.DeserializeObject<ClassWithItemConverterAttribute>(json, this.settings);

        Assert.IsNotNull(result);
        var list = result.EnumValues.ToList();
        Assert.AreEqual(3, list.Count);
        Assert.AreEqual(TestEnum.Value1, list[0]);
        Assert.AreEqual(TestEnum.Unknown, list[1]);
        Assert.AreEqual(TestEnum.Unknown, list[2]);
    }

    [TestMethod]
    public void DeserializeEnumList_WithItemConverterAttribute_UnknownValues_UsesTolerantConverter()
    {
        // This test covers concrete collection types (e.g. List<T>) with ItemConverterType attributes.
        // Unlike IEnumerable<T>, List<T> is not itself IEnumerable<> — it only *implements* it,
        // so IsEnumCollectionType must check type.GetInterfaces() to detect it.
        var json = @"{ ""EnumValues"": [""Value1"", ""UnknownEnum"", ""Value2""] }";
        var result = JsonConvert.DeserializeObject<ClassWithListAndItemConverterAttribute>(json, this.settings);

        Assert.IsNotNull(result);
        Assert.AreEqual(3, result.EnumValues.Count);
        Assert.AreEqual(TestEnum.Value1, result.EnumValues[0]);
        Assert.AreEqual(TestEnum.Unknown, result.EnumValues[1]);
        Assert.AreEqual(TestEnum.Value2, result.EnumValues[2]);
    }
}
