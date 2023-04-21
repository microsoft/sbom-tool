// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using HashAlgorithmName = Microsoft.Sbom.Contracts.Enums.AlgorithmName;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Utils;

/// <summary>
/// Provides helper functions to generate identity strings for SPDX.
/// </summary>
public static class InternalMetadataProviderIdentityExtensions
{
    /// <summary>
    /// Get the name of the package. This can be provided directly be the user, or
    /// if not, we can try to generate one based on the build parameters.
    /// 
    /// If we are unable to generate a package name, we throw an <see cref="ArgumentException"/>
    /// exception.
    /// </summary>
    /// <returns>The string package name.</returns>
    public static string GetPackageName(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        // First check if the user provided a package name.
        if (internalMetadataProvider.TryGetMetadata(MetadataKey.PackageName, out string packageName))
        {
            return packageName;
        }

        // If the build name is provided, use it as the name.
        if (internalMetadataProvider.TryGetMetadata(MetadataKey.Build_DefinitionName, out string buildDefName))
        {
            return buildDefName;
        }

        // Right now we don't have any better way to name the package. Throw an exception for the user to 
        // provide a package name.
        throw new ArgumentException($"Unable to generate a package name based on provided parameters. " +
                                    $"Please provide the package name in the 'PackageName' parameter.");
    }

    /// <summary>
    /// Generates the package verification code for a given package using the SPDX 2.2 specification.
    /// 
    /// Algorithm defined here https://spdx.github.io/spdx-spec/3-package-information/#39-package-verification-code.
    /// </summary>
    /// <param name="internalMetadataProvider"></param>
    /// <returns></returns>
    public static PackageVerificationCode GetPackageVerificationCode(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        // Get a list of SHA1 checksums
        IList<string> sha1Checksums = new List<string>();
        foreach (var checksumArray in internalMetadataProvider.GetGenerationData(Constants.Spdx22ManifestInfo).Checksums)
        {
            sha1Checksums.Add(checksumArray
                .Where(c => c.Algorithm == HashAlgorithmName.SHA1)
                .Select(c => c.ChecksumValue)
                .FirstOrDefault());
        }

        var packageChecksumString = string.Join(string.Empty, sha1Checksums.OrderBy(s => s));
#pragma warning disable CA5350 // Suppress Do Not Use Weak Cryptographic Algorithms as we use SHA1 intentionally
        var sha1Hasher = SHA1.Create();
#pragma warning restore CA5350
        var hashByteArray = sha1Hasher.ComputeHash(Encoding.Default.GetBytes(packageChecksumString));

        return new PackageVerificationCode
        {
            PackageVerificationCodeValue = BitConverter
                .ToString(hashByteArray)
                .Replace("-", string.Empty)
                .ToLowerInvariant(),
            PackageVerificationCodeExcludedFiles = null // We currently don't ignore any files.
        };
    }

    /// <summary>
    /// Gets a list of file ids that are included in this package.
    /// </summary>
    /// <param name="internalMetadataProvider"></param>
    /// <returns></returns>
    public static List<string> GetPackageFilesList(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        return internalMetadataProvider.GetGenerationData(Constants.Spdx22ManifestInfo).FileIds.ToList();
    }

    /// <summary>
    /// Get the version of the package. This can be provided directly be the user, or
    /// if not, we can try to generate one based on the build parameters.
    /// 
    /// If we are unable to generate a package name, we throw an <see cref="ArgumentException"/>
    /// exception.
    /// </summary>
    /// <returns>The string package version.</returns>
    public static string GetPackageVersion(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        // First check if the user provided a package version.
        if (internalMetadataProvider.TryGetMetadata(MetadataKey.PackageVersion, out string packageVersion))
        {
            return packageVersion;
        }

        // If the build id is provided, use that as version.
        if (internalMetadataProvider.TryGetMetadata(MetadataKey.Build_BuildId, out string buildId))
        {
            return buildId;
        }

        // Right now we don't have any better way to version the package. Throw an exception for the user to 
        // provide a package version.
        throw new ArgumentException($"Unable to generate a package version based on provided parameters. " +
                                    $"Please provide the package version in the 'PackageVersion' parameter.");
    }

    public static string GetPackageSupplier(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        // First check if the user provided a package version.
        if (internalMetadataProvider.TryGetMetadata(MetadataKey.PackageSupplier, out object packageSupplier))
        {
            return packageSupplier as string;
        }

        // Right now we don't have any better way to version the package. Throw an exception for the user to 
        // provide a package version.
        throw new ArgumentException($"Unable to generate a package supplier based on provided parameters. " +
                                    $"Please provide the package supplier in the 'PackageSupplier' parameter.");
    }
 
    public static string GetDocumentNamespace(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        return internalMetadataProvider.GetSBOMNamespaceUri();
    }

    public static string GetGenerationTimestamp(this IInternalMetadataProvider internalMetadataProvider)
    {
        if (internalMetadataProvider is null)
        {
            throw new ArgumentNullException(nameof(internalMetadataProvider));
        }

        if (internalMetadataProvider.TryGetMetadata(MetadataKey.GenerationTimestamp, out object generationTimestamp))
        {
            return generationTimestamp as string;
        }

        return DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
    }
}