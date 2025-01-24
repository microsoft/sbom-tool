// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

/// <summary>
/// Refers to any object that stores content on a computer.
/// The type of content can optionally be provided in the contentType property.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Software/Classes/File/
/// An NTIA file specifically describes a file compliant with the NTIA SBOM standard.
/// </summary>
public class NTIAFile : File
{
    public NTIAFile()
    {
        Type = "software_File";
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("software_contentType")]
    public object ContentType { get; set; }

    /// <summary>
    /// Make verification code required for Files. This is an internal requirement, not a requirement from SPDX.
    /// </summary>
    [JsonRequired]
    [JsonPropertyName("verifiedUsing")]
    public override List<PackageVerificationCode> VerifiedUsing { get; set; }
}
