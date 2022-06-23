// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities
{
    /// <summary>
    /// Used to specify a hash code that describes all the individual
    /// files within this package.
    /// </summary>
    public class PackageVerificationCode
    {
        /// <summary>
        /// Gets or sets the actual package verification code as a hex encoded value.
        /// </summary>
        [JsonPropertyName("packageVerificationCodeValue")]
        public string PackageVerificationCodeValue { get; set; }

        /// <summary>
        /// Gets or sets files that were excluded when calculating the package verification code.
        /// </summary>
        [JsonPropertyName("packageVerificationCodeExcludedFiles")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<string> PackageVerificationCodeExcludedFiles { get; set; }
    }
}
