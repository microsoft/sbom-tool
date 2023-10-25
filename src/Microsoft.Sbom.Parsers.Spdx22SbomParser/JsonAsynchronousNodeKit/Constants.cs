// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.JsonAsynchronousNodeKit;

internal static class Constants
{
    /// <summary>
    /// Converts a <see cref="System.Text.Json.JsonTokenType"/> enum to the actual string
    /// representation of the token.
    /// </summary>
    internal static readonly string[] JsonTokenStrings = new string[]
    {
        string.Empty, // None
        "{", // StartObject
        "}", // EndObject
        "[", // StartArray
        "]", // EndArray
        "PropertyName", // PropertyName
        "Comment", // Comment
        "String", // String
        "Number", // Number
        "True", // True
        "False", // False
        "Null", // Null
    };
}
