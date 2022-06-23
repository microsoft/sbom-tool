// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using Microsoft.Sbom.Extensions.Entities;
using System.Collections.Generic;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Api.Config.Args
{
    /// <summary>
    /// The command line arguments provided for the validate action in ManifestTool.
    /// </summary>
    public class ValidationArgs : CommonArgs
    {
        /// <summary>
        /// Gets or sets the root folder of the drop directory to validate.
        /// </summary>
        [ArgShortcut("b")]
        [ArgRequired(IfNot = "ConfigFilePath")]
        [ArgDescription("The root folder of the drop directory to validate.")]
        public string BuildDropPath { get; set; }

        /// <summary>
        /// Gets or sets the path to the _manifest folder..
        /// </summary>
        [ArgShortcut("m")]
        [ArgDescription("The path of the directory where the manifest will be validated." +
             " If this parameter is not specified, the manifest will be validated in {BuildDropPath}/_manifest directory.")]
        public string ManifestDirPath { get; set; }

        /// <summary>
        /// Gets or sets the path where the output json should be written.
        /// </summary>
        [ArgShortcut("o")]
        [ArgRequired(IfNot = "ConfigFilePath")]
        [ArgDescription("The path where the output json should be written.")]
        public string OutputPath { get; set; }

        /// <summary>
        /// Gets or sets the path of the signed catalog file used to validate the manifest.json.
        /// </summary>
        [ArgDescription("The path of signed catalog file that is used to verify the signature of the manifest json file.")]
        public string CatalogFilePath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether if set, will validate the manifest using the signed catalog file.
        /// </summary>
        [ArgShortcut("s")]
        [ArgDescription("If set, will validate the manifest using the signed catalog file.")]
        public bool ValidateSignature { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether if set, will not fail validation on the files presented in Manifest but missing on the disk.
        /// </summary>
        [ArgShortcut("im")]
        [ArgDescription("If set, will not fail validation on the files presented in Manifest but missing on the disk.")]
        public bool IgnoreMissing { get; set; }

        /// <summary>
        /// Gets or sets if you're downloading only a part of the drop using the '-r' or 'root' parameter
        /// in the drop client, specify the same string value here in order to skip
        /// validating paths that are not downloaded.
        /// </summary>
        [ArgDescription(@"If you're downloading only a part of the drop using the '-r' or 'root' parameter in the drop client, specify the same string value here in order to skip validating paths that are not downloaded.")]
        [ArgShortcut("r")]
        public string RootPathFilter { get; set; }

        /// <summary>
        /// Gets or sets the Hash algorithm to use while verifying or generating the hash value of a file.
        /// </summary>
        [ArgDescription("The Hash algorithm to use while verifying or generating the hash value of a file")]
        public AlgorithmName HashAlgorithm { get; set; }
    }
}