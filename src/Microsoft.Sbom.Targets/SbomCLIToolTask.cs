// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

/// <summary>
/// MSBuild ToolTask for generating an SBOM using the SBOM CLI tool
/// </summary>
public partial class GenerateSbom : ToolTask
{
    /// <summary>
    /// Path to the SBOM CLI tool
    /// </summary>
    [Required]
    public string SbomToolPath { get; set; }

    protected override string ToolName => "Microsoft.Sbom.Tool";

    /// <summary>
    /// Get full path to SBOM CLI tool.
    /// </summary>
    /// <returns></returns>
    protected override string GenerateFullPathToTool()
    {
        return $"{this.SbomToolPath}\\{this.ToolName}.exe";
    }

    /// <summary>
    /// Return a formatted list of arguments for the SBOM CLI tool.
    /// </summary>
    /// <returns>string list of args</returns>
    protected override string GenerateCommandLineCommands()
    {
        return "Command";
    }

    /// <summary>
    /// Validates the SBOM CLI tool parameters
    /// </summary>
    /// <returns></returns>
    protected override bool ValidateParameters()
    {
        return true;
    }
}
