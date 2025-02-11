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

    public GenerationResult(List<FileValidationResult> errors, Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> serializerToJsonDocuments)
    {
        Errors = errors;
        SerializerToJsonDocuments = serializerToJsonDocuments;
    }
}
