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
    public List<FileValidationResult> Errors { get; }

    public IReadOnlyDictionary<IManifestToolJsonSerializer, List<JsonDocument>> SerializerToJsonDocuments { get; }

    public IReadOnlyDictionary<ISbomConfig, bool> JsonArrayStartedForConfig { get; }

    /// <summary>
    /// Result from generators. This result is used to write to the SBOM manifest file.
    /// </summary>
    /// <param name="errors">List of FileValidationResult errors.</param>
    /// <param name="serializerToJsonDocuments">Dictionary to map serializer to the JSON document that should be written to it.</param>
    /// <param name="jsonArrayStartedForConfig">This value determines whether a JSON array for a section is started for the specified config. This is only used for SPDX 2.2 SBOM generation.</param>
    public GenerationResult(List<FileValidationResult> errors, IReadOnlyDictionary<IManifestToolJsonSerializer, List<JsonDocument>> serializerToJsonDocuments, IReadOnlyDictionary<ISbomConfig, bool> jsonArrayStartedForConfig)
    {
        Errors = errors;
        SerializerToJsonDocuments = serializerToJsonDocuments;
        JsonArrayStartedForConfig = jsonArrayStartedForConfig;
    }
}
