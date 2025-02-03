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
public class GenerateResult
  {
      public List<FileValidationResult> Errors { get; set; }

      public Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> SerializerToJsonDocuments { get; set; }

      public GenerateResult(List<FileValidationResult> errors, Dictionary<IManifestToolJsonSerializer, List<JsonDocument>> serializerToJsonDocuments)
      {
          Errors = errors;
          SerializerToJsonDocuments = serializerToJsonDocuments;
      }

    // TODO: add an optional header name? so that you don't have to hardcode it in the Spdx2SerializationStrategy
}
