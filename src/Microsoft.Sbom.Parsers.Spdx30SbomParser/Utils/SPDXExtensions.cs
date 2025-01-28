// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Utils;

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
    /// Returns the SPDX-compliant ID for a general element.
    /// <paramref name="element"/> The element to generate the ID for.
    /// <paramref name="id"/> The ID that uniquely identifies an element to generate the hash for.
    /// </summary>
    public static string GenerateSpdxId(Element element, string id) => $"SPDXRef-{element.Type}-{GetStringHash(id)}";

    /// <summary>
    /// Returns the SPDX-compliant external document ID.
    /// </summary>
    public static string GenerateSpdxExternalDocumentId(string fileName, string sha1Value)
    {
        var spdxExternalDocumentId = $"DocumentRef-{fileName}-{sha1Value}";
        return SpdxIdAllowedCharsRegex.Replace(spdxExternalDocumentId, "-");
    }

    /// <summary>
    /// Get's an ID that corresponds to the package info
    /// </summary>
    /// <param name="spdxPackage"></param>
    /// <param name="packageInfo"></param>
    /// <returns>Package ID that encapsulates unique info about a package.</returns>
    public static string GetSpdxElementId(SbomPackage packageInfo)
    {
        if (packageInfo is null)
        {
            throw new ArgumentNullException(nameof(packageInfo));
        }

        // Get package identity as package name and package version. If version is empty, just use package name
        var packageIdentity = $"{packageInfo.Type}-{packageInfo.PackageName}";
        if (!string.IsNullOrWhiteSpace(packageInfo.PackageVersion))
        {
            packageIdentity = string.Join("-", packageInfo.Type, packageInfo.PackageName, packageInfo.PackageVersion);
        }

        return packageInfo.Id ?? packageIdentity;
    }

    /// <summary>
    /// Adds a SPDXID property to the given file. The id of the file should be the same
    /// for any build as long as the contents of the file haven't changed.
    /// </summary>
    /// <param name="fileName"></param>
    /// <param name="checksums"></param>
    public static string GetSpdxFileId(string fileName, IEnumerable<Checksum> checksums)
    {
        if (string.IsNullOrEmpty(fileName))
        {
            throw new ArgumentException($"'{nameof(fileName)}' cannot be null or empty.", nameof(fileName));
        }

        if (checksums is null || !checksums.Any(c => c.Algorithm == AlgorithmName.SHA1))
        {
            throw new MissingHashValueException($"The file {fileName} is missing the {HashAlgorithmName.SHA1} hash value.");
        }

        // Get the SHA1 for this file.
        var sha1Value = checksums.Where(c => c.Algorithm == AlgorithmName.SHA1)
            .Select(s => s.ChecksumValue)
            .FirstOrDefault();

        return sha1Value;
    }

    /// <summary>
    /// Adds ExternalSpdxId property to the SPDXExternalDocumentReference based on name and checksum information.
    /// </summary>
    public static void AddExternalSpdxId(this ExternalMap reference, string name, IEnumerable<Checksum> checksums)
    {
        if (reference is null)
        {
            throw new ArgumentNullException(nameof(reference));
        }

        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
        }

        var sha1checksums = checksums.Where(c => c.Algorithm == AlgorithmName.SHA1);
        if (checksums is null || !sha1checksums.Any())
        {
            throw new MissingHashValueException($"The external reference {name} is missing the {HashAlgorithmName.SHA1} hash value.");
        }

        // Get the SHA1 for this file.
        var sha1Value = sha1checksums.FirstOrDefault().ChecksumValue;

        reference.ExternalSpdxId = GenerateSpdxExternalDocumentId(name, sha1Value);
    }

    public static void AddSpdxId(this Element element)
    {
        element.SpdxId = GenerateSpdxId(element, element.Name);
    }

    public static void AddSpdxId(this CreationInfo creationInfo)
    {
        creationInfo.SpdxId = GenerateSpdxId(creationInfo, creationInfo.Id);
    }

    public static void AddSpdxId(this Entities.Relationship relationship)
    {
        relationship.SpdxId = GenerateSpdxId(relationship, relationship.To + relationship.RelationshipType.ToString());
    }

    public static void AddSpdxId(this ExternalIdentifier externalIdentifier)
    {
        externalIdentifier.SpdxId = GenerateSpdxId(externalIdentifier, externalIdentifier.Identifier.ToString());
    }

    public static void AddSpdxId(this ExternalMap externalMap)
    {
        externalMap.SpdxId = GenerateSpdxId(externalMap, externalMap.ExternalSpdxId);
    }

    public static void AddSpdxId(this PackageVerificationCode packageVerificationCode)
    {
        packageVerificationCode.SpdxId = GenerateSpdxId(packageVerificationCode, packageVerificationCode.Algorithm.ToString());
    }

    public static void AddSpdxId(this Element element, string id)
    {
        element.SpdxId = GenerateSpdxId(element, id);
    }

    /// <summary>
    /// Compute the SHA256 string representation (omitting dashes) of a given string
    /// </summary>
    /// <remarks>
    /// TODO:  refactor this into Core as similar functionality is duplicated in a few different places in the codebase
    /// </remarks>
    private static string GetStringHash(string str)
    {
        var hash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(str));
        var spdxId = Convert.ToHexString(hash).Replace("-", string.Empty);
        return spdxId;
    }
}
