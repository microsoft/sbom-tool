// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// Provides an interface to validate a SBOM.
/// </summary>
public interface ISbomValidator
{
    /// <summary>
    /// Validates all the files in a given SBOM with the files present in the build drop path
    /// and writes JSON output to the outputPath file location.
    /// </summary>
    Task<bool> ValidateSbomAsync();

    /// <summary>
    /// Validates all the files in a given SBOM with the files present in the build drop path
    /// and writes JSON output to the outputPath file location.
    /// <param name="buildDropPath">The path to the root of the drop.</param>"
    /// <param name="outputPath">The path to a writeable location where the output json should be written.</param>
    /// <param name="specifications">The list of specifications to use for validation.</param>
    /// <param name="manifestDirPath"/>The path to the directory that contains the _manifest folder. If null then buildDropPath will be used</param>
    /// <param name="validateSignature">If true, validate the signature of the SBOM.</param>
    /// <param name="rootPathFilter">The root path filter to use for validation.</param>
    /// <param name="runtimeConfiguration">The runtime configuration to use for validation.</param>
    /// <param name="algorithmName">The algorithm to use for hashing.</param>
    /// </summary>
    Task<SbomValidationResult> ValidateSbomAsync(
        string buildDropPath,
        string outputPath,
        IList<SbomSpecification> specifications,
        string manifestDirPath = null,
        bool validateSignature = false,
        bool ignoreMissing = false,
        string rootPathFilter = null,
        RuntimeConfiguration runtimeConfiguration = null,
        AlgorithmName algorithmName = null);
}
