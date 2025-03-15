// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Result from GenerateAsync
/// </summary>
public class GenerationResult
{
    public List<FileValidationResult> Errors { get; set; }

    public Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> SerializerToJsonDocuments { get; set; }

    public bool JsonArrayStarted { get; set; }

    /// <summary>
    /// Result from generators. This result is used to write to the SBOM manifest file.
    /// </summary>
    /// <param name="errors">List of FileValidationResult errors.</param>
    /// <param name="serializerToJsonDocuments">Dictionary to map serializer to the JSON document that should be written to it.</param>
    public GenerationResult(List<FileValidationResult> errors, Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> serializerToJsonDocuments, bool jsonArrayStarted = false)
    {
        Errors = errors;
        SerializerToJsonDocuments = serializerToJsonDocuments;
        JsonArrayStarted = jsonArrayStarted;
    }
}
