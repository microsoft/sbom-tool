// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Diagnostics.Tracing;

/// <summary>
/// Validation class used to sanitize and validate arguments passed into
/// the GenerateSbomTask and SbomCLIToolTask
/// </summary>
public partial class GenerateSbom
{
    /// <summary>
    /// Ensure all required arguments are non-null/empty,
    /// and do not contain whitespaces, tabs, or newline characters.
    /// </summary>
    /// <returns>True if the required parameters are valid. False otherwise.</returns>
    public bool ValidateAndSanitizeRequiredParams()
    {
        if (string.IsNullOrWhiteSpace(this.BuildDropPath))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.BuildDropPath)}. Please provide a valid path.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.PackageSupplier))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.PackageSupplier)}. Please provide a valid supplier name.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.PackageName))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.PackageName)}. Please provide a valid name.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.PackageVersion))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.PackageVersion)}. Please provide a valid version number.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.NamespaceBaseUri))
        {
            Log.LogError($"SBOM generation failed: Empty argument detected for {nameof(this.NamespaceBaseUri)}. Please provide a valid URI.");
            return false;
        }

        this.PackageSupplier = Remove_Spaces_Tabs_Newlines(this.PackageSupplier);
        this.PackageName = Remove_Spaces_Tabs_Newlines(this.PackageName);
        this.PackageVersion = Remove_Spaces_Tabs_Newlines(this.PackageVersion);
        this.NamespaceBaseUri = this.NamespaceBaseUri.Trim();
        this.BuildDropPath = this.BuildDropPath.Trim();

        return true;
    }

    public string Remove_Spaces_Tabs_Newlines(string value)
    {
        return value.Replace("\n", string.Empty).Replace("\t", string.Empty).Replace(" ", string.Empty);
    }

    /// <summary>
    /// Checks the user's input for Verbosity and assigns the
    /// associated EventLevel value for logging. The SBOM API accepts
    /// an EventLevel for verbosity while the CLI accepts LogEventLevel.
    /// </summary>
    public EventLevel ValidateAndAssignVerbosity()
    {
        // The following shows the accepted verbosity inputs for the SBOM CLI and API respectively
        // *********************************
        // The SBOM CLI     | The SBOM API |
        // *********************************
        // Verbose          | EventLevel.Verbose
        // Debug            | EventLevel.LogAlways
        // Information      | EventLevel.Informational
        // Warning          | EventLevel.Warning
        // Error            | EventLevel.Error
        // Fatal            | EventLevel.Critical

        // We should standardize on the SBOM CLI verbosity inputs and convert them to the associated
        // EventLevel value for the API.
        if (string.IsNullOrWhiteSpace(this.Verbosity))
        {
            Log.LogWarning($"No verbosity level specified. Setting verbosity level at Verbose");
            this.Verbosity = "Verbose";
            return EventLevel.Verbose;
        }

        switch (this.Verbosity.ToLower().Trim())
        {
            case "verbose":
                return EventLevel.Verbose;
            case "debug":
                return EventLevel.Verbose;
            case "information":
                return EventLevel.Informational;
            case "warning":
                return EventLevel.Warning;
            case "error":
                return EventLevel.Error;
            case "fatal":
                return EventLevel.Critical;
            default:
                Log.LogWarning($"Unrecognized verbosity level specified. Setting verbosity level at Verbose");
                this.Verbosity = "Verbose";
                return EventLevel.Verbose;
        }
    }

    /// <summary>
    /// Ensure a valid NamespaceUriUniquePart is provided.
    /// </summary>
    /// <returns>True if the Namespace URI unique part is valid. False otherwise.</returns>
    public bool ValidateAndSanitizeNamespaceUriUniquePart()
    {
        // Ensure the NamespaceUriUniquePart is valid if provided.
        if (!string.IsNullOrWhiteSpace(this.NamespaceUriUniquePart)
            && (!Guid.TryParse(this.NamespaceUriUniquePart, out _)
            || this.NamespaceUriUniquePart.Equals(Guid.Empty.ToString())))
        {
            Log.LogError($"SBOM generation failed: NamespaceUriUniquePart '{this.NamespaceUriUniquePart}' must be a valid unique GUID.");
            return false;
        }
        else if (!string.IsNullOrWhiteSpace(this.NamespaceUriUniquePart))
        {
            this.NamespaceUriUniquePart = this.NamespaceUriUniquePart.Trim();
        }

        return true;
    }
}
