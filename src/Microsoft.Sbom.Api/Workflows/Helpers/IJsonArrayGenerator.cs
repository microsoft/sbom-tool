// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Used to generate array objects to be written to the JSON serializer.
/// </summary>
public interface IJsonArrayGenerator<T>
    where T : IJsonArrayGenerator<T>
{
    /// <summary>
    /// Generates all the JSON objects that need to be written to the SBOM.
    /// </summary>
    /// <returns>GenerationResult with objects to write to the SBOM and failures.</returns>
    public Task<GenerationResult> GenerateAsync(IEnumerable<ISbomConfig> targetConfigs, ISet<string> elementsSpdxIdList);
}
