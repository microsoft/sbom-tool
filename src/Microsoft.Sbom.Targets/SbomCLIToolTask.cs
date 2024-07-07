// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System.Diagnostics.Tracing;
using System.IO;
using Microsoft.Build.Utilities;

/// <summary>
/// MSBuild ToolTask for generating an SBOM using the SBOM CLI tool
/// </summary>
public partial class GenerateSbom : ToolTask
{
    protected override string ToolName => "Microsoft.Sbom.Tool";

    /// <summary>
    /// Get full path to SBOM CLI tool.
    /// </summary>
    /// <returns></returns>
    protected override string GenerateFullPathToTool()
    {
        return Path.Combine(this.SbomToolPath, $"{this.ToolName}.exe");
    }

    /// <summary>
    /// Return a formatted list of arguments for the SBOM CLI tool.
    /// </summary>
    /// <returns>string list of args</returns>
    protected override string GenerateCommandLineCommands()
    {
        var arguments =
                "generate " +
                $"-BuildDropPath {this.BuildDropPath} " +
                $"-BuildComponentPath {this.BuildComponentPath} " +
                $"-PackageName {this.PackageName} " +
                $"-PackageVersion {this.PackageVersion} " +
                $"-PackageSupplier {this.PackageSupplier} " +
                $"-NamespaceUriBase {this.NamespaceBaseUri} " +
                $"-DeleteManifestDirIfPresent {this.DeleteManifestDirIfPresent} " +
                $"-FetchLicenseInformation {this.FetchLicenseInformation} " +
                $"-EnablePackageMetadataParsing {this.EnablePackageMetadataParsing} " +
                $"-Verbosity {this.Verbosity} ";

        // For optional arguments, append them only if they are specified by the user
        if (!string.IsNullOrEmpty(this.ManifestDirPath))
        {
            arguments += $"-ManifestDirPath {this.ManifestDirPath} ";
        }

        if (!string.IsNullOrEmpty(this.ExternalDocumentListFile))
        {
            arguments += $"-ExternalDocumentListFile {this.ExternalDocumentListFile} ";
        }

        if (!string.IsNullOrEmpty(this.NamespaceUriUniquePart))
        {
            arguments += $"-NamespaceUriUniquePart {this.NamespaceUriUniquePart} ";
        }

        if (!string.IsNullOrEmpty(this.ManifestInfo))
        {
            arguments += $"-ManifestInfo {this.ManifestInfo} ";
        }

        return arguments;
    }

    /// <summary>
    /// Validates the SBOM CLI tool parameters
    /// </summary>
    /// <returns></returns>
    protected override bool ValidateParameters()
    {
        // Validate required args and args that take paths as input.
        if (!ValidateAndSanitizeRequiredParams() || !ValidateAndSanitizeNamespaceUriUniquePart())
        {
            return false;
        }

        var eventLevel = ValidateAndAssignVerbosity();
        SetOutputImportance(eventLevel);
        return true;
    }

    /// <summary>
    /// This method sets the standard output importance. Setting
    /// it to "High" ensures all output from the SBOM CLI is printed to
    /// Visual Studio's output console; otherwise, it is hidden.
    /// </summary>
    /// <param name="eventLevel"></param>
    private void SetOutputImportance(EventLevel eventLevel)
    {
        this.StandardOutputImportance = "High";

        if (eventLevel == EventLevel.Critical)
        {
            this.StandardOutputImportance = "Low";
        }
    }
}
