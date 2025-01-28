// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Args;

/// <summary>
/// The command line arguments provided for the validate action in ManifestTool.
/// </summary>
public class FormatValidationArgs : CommonArgs
{
    /// <summary>
    /// Gets or sets the file path of the SBOM to validate.
    /// </summary>
    [ArgShortcut("sp")]
    [ArgDescription("The file path of the SBOM to validate.")]
    public string? SbomPath { get; set; }
}
