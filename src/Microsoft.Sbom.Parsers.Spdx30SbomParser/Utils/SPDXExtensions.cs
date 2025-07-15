// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Extensions.Exceptions;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Utils;

/// <summary>
/// Provides extensions to SPDX objects.
/// </summary>
public static class SPDXExtensions
{
    private const string SpdxIdPrefix = "SPDXRef";

    /// <summary>
    /// Adds SPDX ID that corresponds to the package info.
    /// </summary>
    /// <param name="spdxPackage"></param>
    /// <param name="packageInfo"></param>
    /// <returns>Package ID that encapsulates unique info about a package.</returns>
    public static string AddSpdxId(this Package spdxPackage, SbomPackage packageInfo)
    {
        spdxPackage.SpdxId = CommonSPDXUtils.GenerateSpdxPackageId(packageInfo);
        return spdxPackage.SpdxId;
    }

    public static string AddSpdxId(this File element, InternalSbomFileInfo fileInfo)
    {
        if (string.IsNullOrEmpty(fileInfo.Path))
        {
            throw new ArgumentException("Parameter cannot be null or empty.", nameof(fileInfo.Path));
        }

        if (fileInfo.Checksum is null || !fileInfo.Checksum.Any(c => c.Algorithm == AlgorithmName.SHA1))
        {
            throw new MissingHashValueException($"The file {fileInfo.Path} is missing the {HashAlgorithmName.SHA1} hash value.");
        }

        // Get the SHA1 for this file.
        var sha1Value = fileInfo.Checksum.Where(c => c.Algorithm == AlgorithmName.SHA1)
            .Select(s => s.ChecksumValue)
            .FirstOrDefault();

        element.SpdxId = CommonSPDXUtils.GenerateSpdxFileId(fileInfo.Path, sha1Value);
        return element.SpdxId;
    }

    /// <summary>
    /// Adds ExternalSpdxId property to the SPDXExternalDocumentReference based on name and checksum information.
    /// </summary>
    public static string AddExternalSpdxId(this ExternalMap reference, string name, IEnumerable<Checksum> checksums)
    {
        if (reference is null)
        {
            throw new ArgumentNullException(nameof(reference));
        }

        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("Parameter cannot be null or empty.", nameof(name));
        }

        var sha1checksums = checksums.Where(c => c.Algorithm == AlgorithmName.SHA1);
        if (checksums is null || !sha1checksums.Any())
        {
            throw new MissingHashValueException($"The external reference {name} is missing the {HashAlgorithmName.SHA1} hash value.");
        }

        // Get the SHA1 for this file.
        var sha1Value = sha1checksums.FirstOrDefault().ChecksumValue;

        reference.SpdxId = CommonSPDXUtils.GenerateSpdxExternalDocumentId(name, sha1Value);
        return reference.SpdxId;
    }

    public static void AddSpdxId(this Element element)
    {
        element.SpdxId = GenerateSpdxIdBasedOnElement(element, element.Name);
    }

    public static void AddSpdxId(this CreationInfo creationInfo)
    {
        creationInfo.SpdxId = GenerateSpdxIdBasedOnElement(creationInfo, creationInfo.Id);
    }

    public static void AddSpdxId(this Common.Spdx30Entities.Relationship relationship)
    {
        var relationshipToString = string.Empty;
        if (relationship?.To is not null && relationship.To.Any())
        {
            relationshipToString = string.Concat(relationship.To);
        }

        relationship.SpdxId = GenerateSpdxIdBasedOnElement(relationship, relationship.From + relationshipToString + relationship.RelationshipType.ToString());
    }

    public static void AddSpdxId(this ExternalIdentifier externalIdentifier)
    {
        externalIdentifier.SpdxId = GenerateSpdxIdBasedOnElement(externalIdentifier, externalIdentifier.Identifier);
    }

    public static void AddSpdxId(this PackageVerificationCode packageVerificationCode)
    {
        packageVerificationCode.SpdxId = GenerateSpdxIdBasedOnElement(packageVerificationCode, packageVerificationCode.Algorithm.ToString());
    }

    public static string GenerateSpdxIdBasedOnElement(Element element, string id)
    {
        var uniqueIdentifier = CommonSPDXUtils.GenerateHashBasedOnId(id);
        return $"{SpdxIdPrefix}-{element.Type}-{uniqueIdentifier}";
    }
}
