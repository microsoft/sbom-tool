// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// SBOM redactor that removes file information from SBOMs
/// </summary>
public interface ISbomRedactor
{
    public Task<SbomRequiredProperties> RedactSbomAsync(IValidatedSbom sbom);
}
