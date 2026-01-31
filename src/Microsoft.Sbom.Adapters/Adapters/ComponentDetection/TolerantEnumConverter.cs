// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Newtonsoft.Json;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

/// <summary>
/// A JSON converter that handles unknown enum values gracefully by returning a default value
/// instead of throwing an exception. This is useful when deserializing JSON from external sources
/// where enum values may change over time.
/// </summary>
public class TolerantEnumConverter : JsonConverter
{
    /// <summary>
    /// Determines whether this converter can convert the specified object type.
    /// </summary>
    /// <param name="objectType">The type of object to convert.</param>
    /// <returns>True if the type is an enum or nullable enum; otherwise, false.</returns>
    public override bool CanConvert(Type objectType)
    {
        var type = IsNullableType(objectType) ? Nullable.GetUnderlyingType(objectType) : objectType;
        return type?.IsEnum == true;
    }

    /// <summary>
    /// Reads the JSON representation of the object and converts it to the appropriate enum value.
    /// If the value cannot be parsed, returns a default value of -1 (Unknown) if defined,
    /// otherwise returns the first enum value.
    /// </summary>
    /// <param name="reader">The JSON reader.</param>
    /// <param name="objectType">The type of object to convert.</param>
    /// <param name="existingValue">The existing value of object being read.</param>
    /// <param name="serializer">The JSON serializer.</param>
    /// <returns>The converted enum value, or a default value if the value is unknown.</returns>
    public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer)
    {
        var isNullable = IsNullableType(objectType);
        var enumType = isNullable ? Nullable.GetUnderlyingType(objectType)! : objectType;

        if (reader.TokenType == JsonToken.Null)
        {
            if (isNullable)
            {
                return null;
            }

            return GetDefaultEnumValue(enumType);
        }

        try
        {
            if (reader.TokenType == JsonToken.String)
            {
                var enumText = reader.Value?.ToString();
                if (string.IsNullOrEmpty(enumText))
                {
                    return isNullable ? null : GetDefaultEnumValue(enumType);
                }

                // Try to parse the enum value
                if (Enum.TryParse(enumType, enumText, ignoreCase: true, out var result))
                {
                    return result;
                }

                // If parsing fails, return the default value
                return GetDefaultEnumValue(enumType);
            }

            if (reader.TokenType == JsonToken.Integer)
            {
                var enumValue = Convert.ToInt32(reader.Value);

                // Check if the value is defined in the enum
                if (Enum.IsDefined(enumType, enumValue))
                {
                    return Enum.ToObject(enumType, enumValue);
                }

                // If the value is not defined, return the default value
                return GetDefaultEnumValue(enumType);
            }
        }
        catch
        {
            // If any exception occurs during parsing, return the default value
            return isNullable ? null : GetDefaultEnumValue(enumType);
        }

        // For any other token type, return the default value
        return isNullable ? null : GetDefaultEnumValue(enumType);
    }

    /// <summary>
    /// Writes the JSON representation of the object.
    /// </summary>
    /// <param name="writer">The JSON writer.</param>
    /// <param name="value">The value to write.</param>
    /// <param name="serializer">The JSON serializer.</param>
    public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
    {
        if (value == null)
        {
            writer.WriteNull();
            return;
        }

        writer.WriteValue(value.ToString());
    }

    /// <summary>
    /// Gets the default enum value. Tries to find a value named "Unknown" or with value -1,
    /// otherwise returns the first enum value.
    /// </summary>
    /// <param name="enumType">The enum type.</param>
    /// <returns>The default enum value.</returns>
    private static object GetDefaultEnumValue(Type enumType)
    {
        // First, try to find a value named "Unknown" (case-insensitive)
        if (Enum.TryParse(enumType, "Unknown", ignoreCase: true, out var unknownValue))
        {
            return unknownValue!;
        }

        // Then, try to find a value with -1
        try
        {
            var negativeOne = Enum.ToObject(enumType, -1);
            if (Enum.IsDefined(enumType, negativeOne))
            {
                return negativeOne;
            }
        }
        catch
        {
            // Ignore if -1 is not a valid value for this enum
        }

        // Finally, return the first defined value (usually 0)
        var values = Enum.GetValues(enumType);
        if (values.Length > 0)
        {
            return values.GetValue(0)!;
        }

        // This should never happen for a valid enum
        return Activator.CreateInstance(enumType)!;
    }

    /// <summary>
    /// Determines whether the specified type is a nullable type.
    /// </summary>
    /// <param name="type">The type to check.</param>
    /// <returns>True if the type is nullable; otherwise, false.</returns>
    private static bool IsNullableType(Type type)
    {
        return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>);
    }
}
