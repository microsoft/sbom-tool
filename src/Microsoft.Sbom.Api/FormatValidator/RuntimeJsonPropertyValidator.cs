// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.FormatValidator;

using System;
using System.Linq;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Sbom.Common.Utils;

// Use this class to ignore or require JSON properties at runtime.
// Specify the type being deserialized (e.g. IEnumerable<SPDXFile>) as either ignored or required.
// Then set UpdateTypeIgnoreOrRequire as a JsonSerializerOptions.TypeInfoResolver.Modifiers.
public class RuntimeJsonPropertyValidator
{
    private readonly Type[] ignoredTypes;
    private readonly Type[] requiredTypes;

    public RuntimeJsonPropertyValidator(Type[] ignoredTypes, Type[] requiredTypes)
    {
        this.ignoredTypes = ignoredTypes;
        this.requiredTypes = requiredTypes;
    }

    public void UpdateTypeIgnoreOrRequire(JsonTypeInfo info)
    {
        if (info.Kind != JsonTypeInfoKind.Object)
        {
            return;
        }

        // To ignore a Type, remove it from the properties list altogether.
        info.Properties.RemoveAll(p => ignoredTypes.Contains(p.PropertyType));

        foreach (var property in info.Properties)
        {
            if (requiredTypes.Contains(property.PropertyType))
            {
                property.IsRequired = true;
            }
        }
    }
}
