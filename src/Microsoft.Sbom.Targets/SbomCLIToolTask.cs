// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System.IO;
using Microsoft.Build.Utilities;

/// <summary>
/// MSBuild ToolTask for generating an SBOM using the SBOM CLI tool
/// </summary>
public partial class GenerateSbom : ToolTask
{
    protected override string ToolName => "Microsoft.Sbom.Tool";

    /// <summary>
    /// Executes the SBOM CLI Tool invocation. Need to add extra logic
    /// to set SbomPath to the directory containing the SBOM.
    /// </summary>
    /// <returns></returns>
    public override bool Execute()
    {
        var taskResult = base.Execute();
        // Set the SbomPath output variable
        if (taskResult) {
            if (!string.IsNullOrWhiteSpace(this.ManifestDirPath))
            {
                this.SbomPath = this.ManifestDirPath;
            } else
            {
                this.SbomPath = Path.Combine(this.BuildDropPath, "_manifest");
            }
        }

        return taskResult;
    }

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
        var builder = new CommandLineBuilder();

        builder.AppendSwitch("generate");
        builder.AppendSwitchIfNotNull("-BuildDropPath ", this.BuildDropPath);
        builder.AppendSwitchIfNotNull("-BuildComponentPath ", this.BuildComponentPath);
        builder.AppendSwitchIfNotNull("-PackageName ", this.PackageName);
        builder.AppendSwitchIfNotNull("-PackageVersion ", this.PackageVersion);
        builder.AppendSwitchIfNotNull("-PackageSupplier ", this.PackageSupplier);
        builder.AppendSwitchIfNotNull("-NamespaceUriBase ", this.NamespaceBaseUri);
        builder.AppendSwitchIfNotNull("-DeleteManifestDirIfPresent ", $"{this.DeleteManifestDirIfPresent}");
        builder.AppendSwitchIfNotNull("-FetchLicenseInformation ", $"{this.FetchLicenseInformation}");
        builder.AppendSwitchIfNotNull("-EnablePackageMetadataParsing ", $"{this.EnablePackageMetadataParsing}");
        builder.AppendSwitchIfNotNull("-Verbosity ", this.Verbosity);

        // For optional arguments, append them only if they are specified by the user
        if (!string.IsNullOrWhiteSpace(this.ManifestDirPath))
        {
            builder.AppendSwitchIfNotNull("-ManifestDirPath ", this.ManifestDirPath);
        }

        if (!string.IsNullOrWhiteSpace(this.ExternalDocumentListFile))
        {
            builder.AppendSwitchIfNotNull("-ExternalDocumentListFile ", this.ExternalDocumentListFile);
        }

        if (!string.IsNullOrWhiteSpace(this.NamespaceUriUniquePart))
        {
            builder.AppendSwitchIfNotNull("-NamespaceUriUniquePart ", this.NamespaceUriUniquePart);
        }

        if (!string.IsNullOrWhiteSpace(this.ManifestInfo))
        {
            builder.AppendSwitchIfNotNull("-ManifestInfo ", this.ManifestInfo);
        }

        return builder.ToString();
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

        ValidateAndAssignVerbosity();
        SetOutputImportance();
        return true;
    }

    /// <summary>
    /// This method sets the standard output importance. Setting
    /// it to "High" ensures all output from the SBOM CLI is printed to
    /// Visual Studio's output console; otherwise, it is hidden.
    /// </summary>
    private void SetOutputImportance()
    {
        this.StandardOutputImportance = "High";

        if (this.Verbosity.ToLower().Equals("Fatal"))
        {
            this.StandardOutputImportance = "Low";
        }

        this.LogStandardErrorAsError = true;
    }
}
