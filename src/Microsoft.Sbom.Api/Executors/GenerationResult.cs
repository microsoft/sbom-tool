// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Result from GenerateAsync
/// </summary>
public class GenerationResult
{
    public List<FileValidationResult> Errors { get; set; }

    public Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> SerializerToJsonDocuments { get; set; }

    public IEnumerable<ISourcesProvider> SourcesProviders { get; set; }

    /// <summary>
    /// Result from generators. This result is used to write to the SBOM manifest file.
    /// </summary>
    /// <param name="errors">List of FileValidationResult errors.</param>
    /// <param name="serializerToJsonDocuments">Dictionary to map serializer to the JSON document that should be written to it.</param>
    /// <param name="sourcesProviders">Only used for the external document reference generator in SPDX 2.2.</param>
    public GenerationResult(List<FileValidationResult> errors, Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> serializerToJsonDocuments, IEnumerable<ISourcesProvider> sourcesProviders = null)
    {
        Errors = errors;
        SerializerToJsonDocuments = serializerToJsonDocuments;
        SourcesProviders = sourcesProviders ?? Enumerable.Empty<ISourcesProvider>();
    }
}
