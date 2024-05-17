// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Args;

/// <summary>
/// The command line arguments provided for the redact action in ManifestTool.
/// </summary>
public class RedactArgs : CommonArgs
{
    /// <summary>
    /// Gets or sets the file path of the SBOM to redact.
    /// </summary>
    [ArgShortcut("sp")]
    [ArgDescription("The file path of the SBOM to redact.")]
    public string? SbomPath { get; set; }

    /// <summary>
    /// Gets or sets the directory containing the sbom(s) to redact.
    /// </summary>
    [ArgShortcut("sd")]
    [ArgDescription("The directory containing the sbom(s) to redact.")]
    public string? SbomDir { get; set; }

    /// <summary>
    /// Gets or sets the root folder of the drop directory for which the redacted SBOM file will be generated.
    /// </summary>
    [ArgShortcut("b")]
    [ArgDescription("The root folder of the drop directory for which the redacted SBOM file will be generated.")]
    public string BuildDropPath { get; set; }
}
