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

public class NTIAMinConformanceEnforcer : IConformanceEnforcer
{
    private static readonly IReadOnlyCollection<string> EntitiesWithDifferentNTIAMinRequirements = new List<string>
    {
        "SpdxDocument",
        "File",
    };

    public ConformanceType Conformance => ConformanceType.None;

    public string GetConformanceEntityType(string? entityType)
    {
        if (EntitiesWithDifferentNTIAMinRequirements.Contains(entityType))
        {
            return string.IsNullOrEmpty(entityType) ? string.Empty : "NTIAMin" + entityType.GetCommonEntityType();
        }
        else
        {
            return entityType.GetCommonEntityType();
        }
    }

    public void AddInvalidElementsIfDeserializationFails(string jsonObjectAsString, JsonSerializerOptions jsonSerializerOptions, ISet<InvalidElementInfo> invalidElements, Exception e)
    {
        try
        {
            var deserializedAsElement = JsonSerializer.Deserialize(jsonObjectAsString, typeof(Element), jsonSerializerOptions) as Element;
            var invalidElementInfo = GetInvalidElementInfo(deserializedAsElement, errorType: NTIAMinErrorType.InvalidNTIAMinElement);
            invalidElements.Add(invalidElementInfo);
        }
        catch
        {
            throw new ParserException(e.Message);
        }
    }

    /// <summary>
    /// Add invalid NTIAMin elements to the list of invalid elements after deserialization.
    /// </summary>
    public void AddInvalidElements(ElementsResult elementsResult)
    {
        ValidateSbomDocCreationForNTIAMin(elementsResult.SpdxDocuments, elementsResult.CreationInfos, elementsResult.InvalidConformanceElements);
        ValidateSbomFilesForNTIAMin(elementsResult.Files, elementsResult.InvalidConformanceElements);
        ValidateSbomPackagesForNTIAMin(elementsResult.Packages, elementsResult.InvalidConformanceElements);
    }

    /// <summary>
    /// Validate that information about the SBOM document is present.
    /// </summary>
    /// <exception cref="ParserException"></exception>
    private void ValidateSbomDocCreationForNTIAMin(List<SpdxDocument> spdxDocuments, List<CreationInfo> creationInfos, HashSet<InvalidElementInfo> invalidElements)
    {
        // There should only be one SPDX document element in the SBOM.
        if (spdxDocuments.Count == 0)
        {
            invalidElements.Add(GetInvalidElementInfo(null, errorType: NTIAMinErrorType.MissingValidSpdxDocument));
        }
        else if (spdxDocuments.Count > 1)
        {
            invalidElements.UnionWith(spdxDocuments.Select(
                spdxDocument => GetInvalidElementInfo(spdxDocument, errorType: NTIAMinErrorType.AdditionalSpdxDocument)));
        }
        else
        {
            var spdxDocumentElement = spdxDocuments.First();
            var spdxCreationInfoElement = creationInfos.
                FirstOrDefault(element => element.Id == spdxDocumentElement.CreationInfoDetails);

            if (spdxCreationInfoElement is null)
            {
                invalidElements.Add(GetInvalidElementInfo(null, errorType: NTIAMinErrorType.MissingValidCreationInfo));
            }
        }
    }

    /// <summary>
    /// Validate that all files have declared and concluded licenses.
    /// </summary>
    /// <exception cref="ParserException"></exception>
    private void ValidateSbomFilesForNTIAMin(List<File> files, HashSet<InvalidElementInfo> invalidElements)
    {
        foreach (var file in files)
        {
            var fileHasSha256Hash = file.VerifiedUsing?.
                Any(packageVerificationCode => packageVerificationCode.Algorithm == HashAlgorithm.sha256);

            if (fileHasSha256Hash is null || fileHasSha256Hash == false)
            {
                invalidElements.Add(GetInvalidElementInfo(file, errorType: NTIAMinErrorType.InvalidNTIAMinElement));
            }
        }
    }

    /// <summary>
    /// Validate that all packages have declared and concluded licenses.
    /// </summary>
    /// <exception cref="ParserException"></exception>
    private void ValidateSbomPackagesForNTIAMin(List<Package> packages, HashSet<InvalidElementInfo> invalidElements)
    {
        foreach (var package in packages)
        {
            var packageHasSha256Hash = package.VerifiedUsing?.
                Any(packageVerificationCode => packageVerificationCode.Algorithm == HashAlgorithm.sha256);

            if (packageHasSha256Hash is null || packageHasSha256Hash == false)
            {
                invalidElements.Add(GetInvalidElementInfo(package, errorType: NTIAMinErrorType.InvalidNTIAMinElement));
            }
        }
    }

    private InvalidElementInfo GetInvalidElementInfo(Element? element, IConformanceErrorType errorType)
    {
        return new InvalidElementInfo(element?.Name, element?.SpdxId, errorType);
    }
}
