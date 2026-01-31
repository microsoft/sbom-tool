// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Reflection;
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
    protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
    {
        var property = base.CreateProperty(member, memberSerialization);

        // If the property type is an enum or nullable enum, use our tolerant converter
        if (property.PropertyType != null && IsEnumType(property.PropertyType))
        {
            property.Converter = TolerantConverter;
        }

        // If the property is a collection of enums, set the item converter
        if (property.PropertyType != null && IsEnumCollectionType(property.PropertyType))
        {
            property.ItemConverter = TolerantConverter;
        }

        return property;
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

        // Check if it's a generic collection (IEnumerable<T>, List<T>, etc.) of enums
        if (type.IsGenericType)
        {
            var genericArgs = type.GetGenericArguments();
            if (genericArgs.Length == 1 && IsEnumType(genericArgs[0]))
            {
                var genericDef = type.GetGenericTypeDefinition();
                if (typeof(IEnumerable<>).IsAssignableFrom(genericDef) ||
                    genericDef == typeof(List<>) ||
                    genericDef == typeof(IList<>) ||
                    genericDef == typeof(ICollection<>) ||
                    genericDef == typeof(IReadOnlyList<>) ||
                    genericDef == typeof(IReadOnlyCollection<>))
                {
                    return true;
                }

                // Also check if the type implements IEnumerable<EnumType>
                foreach (var iface in type.GetInterfaces())
                {
                    if (iface.IsGenericType &&
                        iface.GetGenericTypeDefinition() == typeof(IEnumerable<>) &&
                        IsEnumType(iface.GetGenericArguments()[0]))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
