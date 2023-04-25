// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;

namespace Microsoft.Sbom;

/// <summary>
/// Provides an interface to validate a SBOM.
/// </summary>
public interface ISBOMValidator
{
    /// <summary>
    /// Validates all the files in a given SBOM with the files present in the build drop path
    /// and writes JSON output to the outputPath file location.
    /// </summary>
    Task<bool> ValidateSbomAsync();
}