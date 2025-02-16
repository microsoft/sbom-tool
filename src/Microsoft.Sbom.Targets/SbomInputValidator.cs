// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;

/// <summary>
/// Validation class used to sanitize and validate arguments passed into
/// the GenerateSbomTask and SbomCLIToolTask
/// </summary>
public partial class GenerateSbom
{
    private const string DefaultVerbosity = "Information";
    private const EventLevel DefaultEventLevel = EventLevel.Informational;

    /// <summary>
    /// Ensure all required arguments are non-null/empty,
    /// and do not contain whitespaces, tabs, or newline characters.
    /// </summary>
    /// <returns>True if the required parameters are valid. False otherwise.</returns>
    public bool ValidateAndSanitizeRequiredParams()
    {
        var requiredProperties = new Dictionary<string, string>
        {
            { nameof(this.BuildDropPath), this.BuildDropPath },
            { nameof(this.PackageSupplier), this.PackageSupplier },
            { nameof(this.PackageName), this.PackageName },
            { nameof(this.PackageVersion), this.PackageVersion },
            { nameof(this.NamespaceBaseUri), this.NamespaceBaseUri }
        };

        foreach (var property in requiredProperties)
        {
            if (string.IsNullOrWhiteSpace(property.Value))
            {
                Log.LogError($"SBOM generation failed: Empty argument detected for {property.Key}. Please provide a valid value.");
                return false;
            }
        }

        this.PackageSupplier = Remove_Tabs_Newlines(this.PackageSupplier);
        this.PackageName = Remove_Tabs_Newlines(this.PackageName);
        this.PackageVersion = Remove_Tabs_Newlines(this.PackageVersion).Replace(" ", string.Empty);
        this.NamespaceBaseUri = this.NamespaceBaseUri.Trim();
        this.BuildDropPath = this.BuildDropPath.Trim();

        return true;
    }

    public string Remove_Tabs_Newlines(string value)
    {
        return value.Replace("\n", string.Empty).Replace("\t", string.Empty).Trim();
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
            Log.LogWarning($"No verbosity level specified. Setting verbosity level at {DefaultVerbosity}.");
            this.Verbosity = DefaultVerbosity;
            return DefaultEventLevel;
        }

        switch (this.Verbosity.ToLower().Trim())
        {
            case "verbose":
                this.Verbosity = "Verbose";
                return EventLevel.Verbose;
            case "debug":
                this.Verbosity = "Verbose";
                return EventLevel.Verbose;
            case "information":
                this.Verbosity = "Information";
                return EventLevel.Informational;
            case "warning":
                this.Verbosity = "Warning";
                return EventLevel.Warning;
            case "error":
                this.Verbosity = "Error";
                return EventLevel.Error;
            case "fatal":
                this.Verbosity = "Fatal";
                return EventLevel.Critical;
            default:
                Log.LogWarning($"Unrecognized verbosity level specified. Setting verbosity level at {DefaultVerbosity}.");
                this.Verbosity = DefaultVerbosity;
                return DefaultEventLevel;
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
