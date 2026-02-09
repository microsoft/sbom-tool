// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// A contract resolver that overrides enum converters with <see cref="TolerantEnumConverter"/>
/// to handle unknown enum values gracefully.
/// </summary>
public class TolerantEnumContractResolver : DefaultContractResolver
{
    private static readonly TolerantEnumConverter TolerantConverter = new TolerantEnumConverter();

    /// <inheritdoc />
    protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
    {
        var properties = base.CreateProperties(type, memberSerialization);

        foreach (var property in properties)
        {
            if (property.PropertyType == null)
            {
                continue;
            }

            // If the property type is an enum or nullable enum, use our tolerant converter
            if (IsEnumType(property.PropertyType))
            {
                property.Converter = TolerantConverter;
            }

            // If the property is a collection of enums, set the item converter
            if (IsEnumCollectionType(property.PropertyType))
            {
                property.ItemConverter = TolerantConverter;
            }
        }

        return properties;
    }

    /// <inheritdoc />
    protected override JsonArrayContract CreateArrayContract(Type objectType)
    {
        var contract = base.CreateArrayContract(objectType);

        // If this is an array/collection of enums, use our tolerant converter for items
        if (contract.CollectionItemType != null && IsEnumType(contract.CollectionItemType))
        {
            contract.ItemConverter = TolerantConverter;
        }

        return contract;
    }

    private static bool IsEnumType(Type type)
    {
        if (type.IsEnum)
        {
            return true;
        }

        var underlyingType = Nullable.GetUnderlyingType(type);
        return underlyingType?.IsEnum == true;
    }

    private static bool IsEnumCollectionType(Type type)
    {
        // Check if it's an array of enums
        if (type.IsArray && IsEnumType(type.GetElementType()!))
        {
            return true;
        }

        // Check if the type itself is IEnumerable<TEnum> (e.g. IEnumerable<ComponentType>)
        if (IsGenericIEnumerableOfEnum(type))
        {
            return true;
        }

        // This covers List<T>, IList<T>, ICollection<T>, IReadOnlyList<T>, and any custom collection.
        foreach (var iface in type.GetInterfaces())
        {
            if (IsGenericIEnumerableOfEnum(iface))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks if the type is a generic IEnumerable of an enum type.
    /// </summary>
    private static bool IsGenericIEnumerableOfEnum(Type type)
    {
        return type.IsGenericType &&
               type.GetGenericTypeDefinition() == typeof(IEnumerable<>) &&
               IsEnumType(type.GetGenericArguments()[0]);
    }
}
