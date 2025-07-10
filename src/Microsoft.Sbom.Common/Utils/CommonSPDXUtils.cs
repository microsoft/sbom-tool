// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Common.Utils;

/// <summary>
/// Provides utility methods for SPDX objects.
/// </summary>
public static class CommonSPDXUtils
{
    /// <summary>
    /// Only these chars are allowed in a SPDX id. Replace all other chars with '-'.
    /// </summary>
    private static readonly Regex SpdxIdAllowedCharsRegex = new Regex("[^a-zA-Z0-9.-]");

    /// <summary>
    /// Returns the SPDX-compliant package ID.
    /// </summary>
    public static string GenerateSpdxPackageId(string id) => $"{Constants.SPDXRefPackage}-{GetStringHash(id)}";

    /// <summary>
    /// Returns the SPDX-compliant package ID from an SbomPackage object.
    /// </summary>
    public static string GenerateSpdxPackageId(SbomPackage packageInfo)
    {
        if (packageInfo is null)
        {
            throw new ArgumentNullException(nameof(packageInfo));
        }

        // Special case to preserve incoming SPDX ID's during aggregation
        if (packageInfo.Id is not null && packageInfo.Id.StartsWith(Constants.SPDXRefPackage, StringComparison.OrdinalIgnoreCase))
        {
            return packageInfo.Id;
        }

        // Get package identity as package name and package version. If version is empty, just use package name
        var packageIdentity = $"{packageInfo.Type}-{packageInfo.PackageName}";
        if (!string.IsNullOrWhiteSpace(packageInfo.PackageVersion))
        {
            packageIdentity = string.Join("-", packageInfo.Type, packageInfo.PackageName, packageInfo.PackageVersion);
        }

        return GenerateSpdxPackageId(packageInfo.Id ?? packageIdentity);
    }

    /// <summary>
    /// Returns the SPDX-compliant file ID.
    /// </summary>
    public static string GenerateSpdxFileId(string fileName, string sha1Value)
    {
        var spdxFileId = $"{Constants.SPDXRefFile}-{fileName}-{sha1Value}";
        return SpdxIdAllowedCharsRegex.Replace(spdxFileId, "-");
    }

    /// <summary>
    /// Returns the SPDX-compliant external document ID.
    /// </summary>
    public static string GenerateSpdxExternalDocumentId(string fileName, string sha1Value)
    {
        var spdxExternalDocumentId = $"{Constants.SPDXRefExternalDocument}-{fileName}-{sha1Value}";
        return SpdxIdAllowedCharsRegex.Replace(spdxExternalDocumentId, "-");
    }

    public static string GenerateHashBasedOnId(string id)
    {
        var hash = GetStringHash(id);
        return SpdxIdAllowedCharsRegex.Replace(hash, "-");
    }

    /// <summary>
    /// Compute the SHA256 string representation (omitting dashes) of a given string
    /// </summary>
    private static string GetStringHash(string str)
    {
        var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(str));
        var spdxId = BitConverter.ToString(hash).Replace("-", string.Empty);
        return spdxId;
    }
}
