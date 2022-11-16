// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Sbom
{
    /// <summary>
    /// Provides an interface to validate a SBOM.
    /// </summary>
    public interface ISBOMValidator
    {
        /// <summary>
        /// Validates all the files in a given SBOM with the files present in the build drop path
        /// and writes JSON output to the outputPath file location.
        /// </summary>
        /// <param name="buildDropPath">The root path of the drop to validate.</param>
        /// <param name="outputPath">The path of the JSON file where the result JSON will be written.</param>
        /// <param name="algorithmName">The algorithm to be used to validate checksums. Default value is SHA256.</param>
        /// <param name="specifications">A list of SBOM formats to validate.</param>
        /// <param name="manifestDirPath">If provided will use this value for the SBOM. Default will search for the _manifest directory in the build drop path.</param>
        /// <param name="validateSignature">If true, we will try to validate the signature of the SBOM using the catalog file.</param>
        /// <param name="ignoreMissing">If true, we will ignore reporting files missing from the disk as errors.</param>
        /// <param name="rootPathFilter">If you're downloading only a part of the drop using the '-r' or 'root' parameter in the
        /// drop client, specify the same string value here in order to skip validating paths that are not downloaded.</param>
        /// <param name="runtimeConfiguration">Additional parameters to configure the SBOM .</param>
        /// <returns></returns>
        Task<bool> ValidateSbomAsync(
            string buildDropPath,
            string outputPath,
            AlgorithmName algorithmName,
            IList<SBOMSpecification> specifications,
            string manifestDirPath,
            bool validateSignature,
            bool ignoreMissing,
            string rootPathFilter,
            RuntimeConfiguration runtimeConfiguration);
    }
}
