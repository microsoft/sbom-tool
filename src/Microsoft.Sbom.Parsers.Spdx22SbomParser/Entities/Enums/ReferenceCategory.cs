// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums
{
    /// <summary>
    /// Defines a Category for an external package reference.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ReferenceCategory
    {
        OTHER,
        SECURITY,
        PACKAGE_MANAGER,
        PERSISTENT_ID
    }
}
