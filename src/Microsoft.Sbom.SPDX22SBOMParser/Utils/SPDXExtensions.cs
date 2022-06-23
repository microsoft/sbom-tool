// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Exceptions;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.SPDX22SBOMParser.Entities;
using Microsoft.SPDX22SBOMParser.Entities.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.SPDX22SBOMParser.Utils
{
    /// <summary>
    /// Provides extensions to SPDX objects.
    /// </summary>
    public static class SPDXExtensions
    {
        /// <summary>
        /// Only these chars are allowed in a SPDX id. Replace all other chars with '-'.
        /// </summary>
        private static readonly Regex SpdxIdAllowedCharsRegex = new Regex("[^a-zA-Z0-9.-]");

        /// <summary>
        ///  "@" chars in the namespace should be url encoded, SPDX SBOM recommendation.
        /// </summary>
        private static readonly Regex PUrlEncodingRegex = new Regex("@", RegexOptions.Compiled);

        /// <summary>
        /// Returns the SPDX-compliant package ID.
        /// </summary>
        public static string GenerateSpdxPackageId(string id) => $"SPDXRef-Package-{GetStringHash(id)}";

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
            var spdxExternalDocumentId = $"DocumentRef-{fileName}-{sha1Value}";
            return SpdxIdAllowedCharsRegex.Replace(spdxExternalDocumentId, "-");
        }

        /// <summary>
        /// Using a <see cref="PackageInfo"/> object, add package urls to the spdxPackage.
        /// </summary>
        /// <param name="spdxPackage">The object to add the external reference to.</param>
        /// <param name="packageInfo">The packageInfo object to use for source data.</param>
        public static void AddPackageUrls(this SPDXPackage spdxPackage, SBOMPackage packageInfo)
        {
            if (spdxPackage is null)
            {
                throw new ArgumentNullException(nameof(spdxPackage));
            }

            if (packageInfo is null)
            {
                return;
            }

            // Add purl information if available.
            if (packageInfo.PackageUrl != null)
            {
                if (spdxPackage.ExternalReferences == null)
                {
                    spdxPackage.ExternalReferences = new List<ExternalReference>();
                }

                // Create a new PURL external reference.
                var extRef = new ExternalReference
                {
                    ReferenceCategory = ReferenceCategory.PACKAGE_MANAGER,
                    Type = ExternalRepositoryType.Purl,
                    Locator = FormatPackageUrl(packageInfo.PackageUrl)
                };

                spdxPackage.ExternalReferences.Add(extRef);
            }
        }

        /// <summary>
        /// Used to encode and format packageurl, specifcally for @ to %40.
        /// </summary>
        /// <param name="packageUrl"></param>
        /// <returns></returns>
        private static string FormatPackageUrl(string packageUrl)
        {
            return PUrlEncodingRegex.Replace(packageUrl, "%40");
        }

        /// <summary>
        /// Adds a SPDXID property to the given package. The id of the package should be the same
        /// for any build as long as the contents of the package haven't changed.
        /// </summary>
        /// <param name="spdxPackage"></param>
        /// <param name="packageInfo"></param>
        public static string AddSpdxId(this SPDXPackage spdxPackage, SBOMPackage packageInfo)
        {
            if (spdxPackage is null)
            {
                throw new ArgumentNullException(nameof(spdxPackage));
            }

            if (packageInfo is null)
            {
                throw new ArgumentNullException(nameof(packageInfo));
            }

            // Get package identity as package name and package version. If version is empty, just use package name
            string packageIdentity = $"{packageInfo.Type}-{packageInfo.PackageName}";
            if (!string.IsNullOrWhiteSpace(packageInfo.PackageVersion))
            {
                packageIdentity = string.Join("-", packageInfo.Type, packageInfo.PackageName, packageInfo.PackageVersion);
            }

            spdxPackage.SpdxId = GenerateSpdxPackageId(packageInfo.Id ?? packageIdentity);
            return spdxPackage.SpdxId;
        }

        /// <summary>
        /// Adds a SPDXID property to the given file. The id of the file should be the same
        /// for any build as long as the contents of the file haven't changed.
        /// </summary>
        /// <param name="spdxFile"></param>
        /// <param name="fileName"></param>
        /// <param name="checksums"></param>
        public static string AddSpdxId(this SPDXFile spdxFile, string fileName, IEnumerable<Sbom.Contracts.Checksum> checksums)
        {
            if (spdxFile is null)
            {
                throw new ArgumentNullException(nameof(spdxFile));
            }

            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentException($"'{nameof(fileName)}' cannot be null or empty.", nameof(fileName));
            }

            if (checksums is null || !checksums.Any(c => c.Algorithm == AlgorithmName.SHA1))
            {
                throw new MissingHashValueException($"The file {fileName} is missing the {HashAlgorithmName.SHA1} hash value.");
            }

            // Get the SHA1 for this file.
            string sha1Value = checksums.Where(c => c.Algorithm == AlgorithmName.SHA1)
                                        .Select(s => s.ChecksumValue)
                                        .FirstOrDefault();

            spdxFile.SPDXId = GenerateSpdxFileId(fileName, sha1Value);
            return spdxFile.SPDXId;
        }

        /// <summary>
        /// Adds externalReferenceId property to the SPDXExternalDocumentReference based on name and checksum information.
        /// </summary>
        public static string AddExternalReferenceSpdxId(this SpdxExternalDocumentReference reference, string name, IEnumerable<Sbom.Contracts.Checksum> checksums)
        {
            if (reference is null)
            {
                throw new ArgumentNullException(nameof(reference));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            if (checksums is null || !checksums.Any(c => c.Algorithm == AlgorithmName.SHA1))
            {
                throw new MissingHashValueException($"The external reference {name} is missing the {HashAlgorithmName.SHA1} hash value.");
            }

            // Get the SHA1 for this file.
            string sha1Value = checksums.Where(c => c.Algorithm == AlgorithmName.SHA1)
                                        .Select(s => s.ChecksumValue)
                                        .FirstOrDefault();

            reference.ExternalDocumentId = GenerateSpdxExternalDocumentId(name, sha1Value);
            return reference.ExternalDocumentId;
        }

        /// Compute the SHA256 string representation (omitting dashes) of a given string
        /// </summary>
        /// <remarks>
        /// TODO:  refactor this into Core as similar functionality is duplicated in a few different places in the codebase
        /// </remarks>
        private static string GetStringHash(string str)
        {
            var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(str)); 
            var spdxId = BitConverter.ToString(hash).Replace("-", string.Empty);
            return spdxId;
        }
    }
}
