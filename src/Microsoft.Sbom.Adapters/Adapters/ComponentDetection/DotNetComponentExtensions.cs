// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Contracts;

internal static class DotNetComponentExtensions
{
    private const string NotApplicablePropertyValue = "-";
    private const string ComponentUnknownPropertyValue = "unknown";

    public static SbomPackage ToSbomPackage(this DotNetComponent dotnetComponent, ExtendedScannedComponent component)
    {
        var sdkVersion = SanitizeString(dotnetComponent.SdkVersion);
        var targetFramework = SanitizeString(dotnetComponent.TargetFramework);
        var projectType = SanitizeString(dotnetComponent.ProjectType);

        string packageName;
        if (string.IsNullOrWhiteSpace(targetFramework) && string.IsNullOrWhiteSpace(projectType))
        {
            packageName = sdkVersion ?? string.Empty;
        }
        else
        {
            packageName = $"{targetFramework} {projectType}".Trim();
        }

        return new()
        {
            Id = dotnetComponent.Id,
            PackageUrl = dotnetComponent.PackageUrl?.ToString(),
            PackageName = packageName,
            PackageVersion = sdkVersion,
            FilesAnalyzed = false,
            Type = "dotnet"
        };
    }

    private static string? SanitizeString(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || string.Equals(value.Trim(), ComponentUnknownPropertyValue, StringComparison.CurrentCultureIgnoreCase)
            || string.Equals(value.Trim(), NotApplicablePropertyValue, StringComparison.CurrentCultureIgnoreCase))
        {
            return null;
        }

        return value.Trim();
    }
}
