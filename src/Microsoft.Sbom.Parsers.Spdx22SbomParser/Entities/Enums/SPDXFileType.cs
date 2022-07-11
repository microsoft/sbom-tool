// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums
{
    /// <summary>
    /// This field provides information about the type of file identified.
    /// Full definition here: https://spdx.github.io/spdx-spec/file-information/#83-file-type-field.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum SPDXFileType
    {
        /// <summary>
        /// The file is an SPDX type.
        /// </summary>
        SPDX,
    }
}
