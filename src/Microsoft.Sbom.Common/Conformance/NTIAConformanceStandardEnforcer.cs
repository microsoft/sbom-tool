// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Common.Conformance.Enums;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Common.Spdx30Entities.Enums;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Conformance.Interfaces;

namespace Microsoft.Sbom.Common.Conformance;

public class NTIAConformanceStandardEnforcer : IConformanceStandardEnforcer
{
    private static readonly IReadOnlyCollection<string> EntitiesWithDifferentNTIARequirements = new List<string>
    {
        "SpdxDocument",
        "File",
    };

    public ConformanceStandardType ConformanceStandard => ConformanceStandardType.None;

    public string GetConformanceStandardEntityType(string? entityType)
    {
        if (EntitiesWithDifferentNTIARequirements.Contains(entityType))
        {
            return string.IsNullOrEmpty(entityType) ? string.Empty : "NTIA" + entityType.GetCommonEntityType();
        }
        else
        {
            return entityType.GetCommonEntityType();
        }
    }

    public void AddInvalidElementsIfDeserializationFails(string jsonObjectAsString, JsonSerializerOptions jsonSerializerOptions, HashSet<InvalidElementInfo> invalidElements, Exception e)
    {
        try
        {
            var deserializedAsElement = JsonSerializer.Deserialize(jsonObjectAsString, typeof(Element), jsonSerializerOptions) as Element;
            var invalidElementInfo = GetInvalidElementInfo(deserializedAsElement, errorType: NTIAErrorType.InvalidNTIAElement);
            invalidElements.Add(invalidElementInfo);
        }
        catch
        {
            throw new ParserException(e.Message);
        }
    }

    /// <summary>
    /// Add invalid NTIA elements to the list of invalid elements after deserialization.
    /// </summary>
    public void AddInvalidElements(ElementsResult elementsResult)
    {
        ValidateSbomDocCreationForNTIA(elementsResult.SpdxDocuments, elementsResult.CreationInfos, elementsResult.InvalidConformanceStandardElements);
        ValidateSbomFilesForNTIA(elementsResult.Files, elementsResult.InvalidConformanceStandardElements);
        ValidateSbomPackagesForNTIA(elementsResult.Packages, elementsResult.InvalidConformanceStandardElements);
    }

    /// <summary>
    /// Validate that information about the SBOM document is present.
    /// </summary>
    /// <param name="elementsList"></param>
    /// <exception cref="ParserException"></exception>
    private void ValidateSbomDocCreationForNTIA(List<SpdxDocument> spdxDocuments, List<CreationInfo> creationInfos, HashSet<InvalidElementInfo> invalidElements)
    {
        // There should only be one SPDX document element in the SBOM.
        if (spdxDocuments.Count == 0)
        {
            invalidElements.Add(GetInvalidElementInfo(null, errorType: NTIAErrorType.MissingValidSpdxDocument));
        }
        else if (spdxDocuments.Count > 1)
        {
            invalidElements.UnionWith(spdxDocuments.Select(
                spdxDocument => GetInvalidElementInfo(spdxDocument, errorType: NTIAErrorType.AdditionalSpdxDocument)));
        }
        else
        {
            var spdxDocumentElement = spdxDocuments.First();
            var spdxCreationInfoElement = creationInfos.
                FirstOrDefault(element => element.Id == spdxDocumentElement.CreationInfoDetails);

            if (spdxCreationInfoElement is null)
            {
                invalidElements.Add(GetInvalidElementInfo(null, errorType: NTIAErrorType.MissingValidCreationInfo));
            }
        }
    }

    /// <summary>
    /// Validate that all files have declared and concluded licenses.
    /// </summary>
    /// <param name="elementsList"></param>
    /// <exception cref="ParserException"></exception>
    private void ValidateSbomFilesForNTIA(List<File> files, HashSet<InvalidElementInfo> invalidElements)
    {
        foreach (var file in files)
        {
            var fileSpdxId = file.SpdxId;

            var fileHasSha256Hash = file.VerifiedUsing?.
                Any(packageVerificationCode => packageVerificationCode.Algorithm == HashAlgorithm.sha256);

            if (fileHasSha256Hash is null || fileHasSha256Hash == false)
            {
                invalidElements.Add(GetInvalidElementInfo(file, errorType: NTIAErrorType.InvalidNTIAElement));
            }
        }
    }

    /// <summary>
    /// Validate that all packages have declared and concluded licenses.
    /// </summary>
    /// <param name="elementsList"></param>
    /// <exception cref="ParserException"></exception>
    private void ValidateSbomPackagesForNTIA(List<Package> packages, HashSet<InvalidElementInfo> invalidElements)
    {
        foreach (var package in packages)
        {
            var packageSpdxId = package.SpdxId;

            var packageHasSha256Hash = package.VerifiedUsing?.
                Any(packageVerificationCode => packageVerificationCode.Algorithm == HashAlgorithm.sha256);

            if (packageHasSha256Hash is null || packageHasSha256Hash == false)
            {
                invalidElements.Add(GetInvalidElementInfo(package, errorType: NTIAErrorType.InvalidNTIAElement));
            }
        }
    }

    private InvalidElementInfo GetInvalidElementInfo(Element? element, IConformanceStandardErrorType errorType)
    {
        return new InvalidElementInfo(element?.Name, element?.SpdxId, errorType);
    }
}
