// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;

namespace Microsoft.Sbom.Parser;

#nullable enable

public abstract class SbomParserTestsBase
{
    public ParserResults Parse(SPDX30Parser parser, Stream? stream = null, bool close = false)
    {
        var results = new ParserResults();

        ParserStateResult? result = null;
        do
        {
            result = parser.Next();

            if (close)
            {
                if (stream is not null)
                {
                    stream.Close();
                }
                else
                {
                    throw new NotImplementedException("Can't close a stream without the stream.");
                }
            }

            if (result is not null && result.Result is not null)
            {
                var jsonElements = result.Result as IEnumerable<object>;
                var jsonList = jsonElements?.ToList();
                results.FormatEnforcedSPDX3Result ??= new FormatEnforcedSPDX3();
                switch (result.FieldName)
                {
                    case SPDX30Parser.ContextProperty:
                        if (jsonList == null || !jsonList.Any() || jsonList.Count > 1)
                        {
                            throw new ParserException($"The context property is either empty or has more than one string.");
                        }
                        else
                        {
                            results.FormatEnforcedSPDX3Result.Context = (string)jsonList.First();
                        }

                        break;
                    case SPDX30Parser.GraphProperty:
                        results.FormatEnforcedSPDX3Result.Graph = ConvertToElements(jsonList, ref results, parser.RequiredComplianceStandard, parser.EntitiesToEnforceComplianceStandardsFor);
                        parser.Metadata = this.SetMetadata(results);
                        break;
                    default:
                        Console.WriteLine($"Unrecognized FieldName: {result.FieldName}");
                        break;
                }
            }
        }
        while (result is not null);

        return results;
    }

    /// <summary>
    /// Converts JSON objects to SPDX elements.
    /// </summary>
    /// <param name="jsonList"></param>
    /// <returns></returns>
    public List<Element> ConvertToElements(List<object>? jsonList, ref ParserResults results, ComplianceStandard? requiredComplianceStandard, IReadOnlyCollection<string>? entitiesWithDifferentNTIARequirements)
    {
        var elementsList = new List<Element>();

        if (jsonList is null)
        {
            return elementsList;
        }

        foreach (JsonObject jsonObject in jsonList)
        {
            var entityType = GetEntityType(jsonObject, requiredComplianceStandard, entitiesWithDifferentNTIARequirements);

            object? deserializedElement = null;
            try
            {
                deserializedElement = JsonSerializer.Deserialize(jsonObject.ToString(), entityType);
            }
            catch (Exception e)
            {
                throw new ParserException(e.Message);
            }

            if (deserializedElement != null)
            {
                elementsList.Add((Element)deserializedElement);

                switch (entityType?.Name)
                {
                    case string name when name.Contains("File"):
                        results.FilesCount += 1;
                        break;
                    case string name when name.Contains("Package"):
                        results.PackagesCount += 1;
                        break;
                    case string name when name.Contains("ExternalMap"):
                        results.ReferencesCount += 1;
                        break;
                    case string name when name.Contains("Relationship"):
                        results.RelationshipsCount += 1;
                        break;
                    default:
                        Console.WriteLine($"Unrecognized entity type: {entityType?.Name}");
                        break;
                }
            }
        }

        // Validate if elements meet required compliance standards
        switch (requiredComplianceStandard)
        {
            case ComplianceStandard.NTIA:
                ValidateNTIARequirements(elementsList);
                break;
        }

        return elementsList;
    }

    public Type GetEntityType(JsonObject jsonObject, ComplianceStandard? requiredComplianceStandard, IReadOnlyCollection<string>? entitiesWithDifferentNTIARequirements)
    {
        var assembly = typeof(Element).Assembly;
        var entityType = jsonObject["type"]?.ToString();

        // For these special cases, remove the prefix from the type.
        switch (entityType)
        {
            case "software_File":
                entityType = "File";
                break;
            case "software_Package":
                entityType = "Package";
                break;
        }

        switch (requiredComplianceStandard)
        {
            case ComplianceStandard.NTIA:
                entityType = "NTIA" + entityType;
                break;
        }

        var type = assembly.GetType($"Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.{entityType}") ?? throw new ParserException($"{entityType} on {jsonObject} is invalid.");

        return type;
    }

    public void ValidateNTIARequirements(List<Element> elementsList)
    {
        ValidateSbomDocCreationForNTIA(elementsList);
        ValidateSbomFilesForNTIA(elementsList);
        ValidateSbomPackagesForNTIA(elementsList);
    }

    /// <summary>
    /// Validate that information about the SBOM document is present.
    /// </summary>
    /// <param name="elementsList"></param>
    /// <exception cref="ParserException"></exception>
    public void ValidateSbomDocCreationForNTIA(List<Element> elementsList)
    {
        var spdxDocumentElements = elementsList.Where(element => element is SpdxDocument);
        if (spdxDocumentElements.Count() != 1)
        {
            throw new ParserException("SBOM document is not NTIA compliant because it must only contain one SpdxDocument element.");
        }

        var spdxDocumentElement = spdxDocumentElements.First();

        var spdxCreationInfoElement = (CreationInfo?)elementsList.
            Where(element => element.Type == nameof(CreationInfo)).
            FirstOrDefault(element => ((CreationInfo)element).Id == spdxDocumentElement.CreationInfoDetails)
            ?? throw new ParserException($"SBOM document is not NTIA compliant because it must have a creationInfo element with ID of {spdxDocumentElement.CreationInfoDetails}");
    }

    /// <summary>
    /// Validate that all files have declared and concluded licenses.
    /// </summary>
    /// <param name="elementsList"></param>
    /// <exception cref="ParserException"></exception>
    public void ValidateSbomFilesForNTIA(List<Element> elementsList)
    {
        var fileElements = elementsList.Where(element => element is NTIAFile);
        foreach (var fileElement in fileElements)
        {
            var fileSpdxId = fileElement.SpdxId;

            var fileHasSha256Hash = fileElement.VerifiedUsing.
                Any(packageVerificationCode => packageVerificationCode.Algorithm ==
                HashAlgorithm.sha256);

            if (!fileHasSha256Hash)
            {
                throw new ParserException($"SBOM document is not NTIA compliant because file with SPDX ID {fileSpdxId} does not have a SHA256 hash.");
            }
        }
    }

    /// <summary>
    /// Validate that all packages have declared and concluded licenses.
    /// </summary>
    /// <param name="elementsList"></param>
    /// <exception cref="ParserException"></exception>
    public void ValidateSbomPackagesForNTIA(List<Element> elementsList)
    {
        var packageElements = elementsList.Where(element => element is Package);
        foreach (var packageElement in packageElements)
        {
            var packageSpdxId = packageElement.SpdxId;

            var packageHasSha256Hash = packageElement.VerifiedUsing.
                Any(packageVerificationCode => packageVerificationCode.Algorithm ==
                HashAlgorithm.sha256);

            if (!packageHasSha256Hash)
            {
                throw new ParserException($"SBOM document is not NTIA compliant because package with SPDX ID {packageSpdxId} does not have a SHA256 hash.");
            }
        }
    }

    /// <summary>
    /// Sets metadata based on parsed SBOM elements.
    /// </summary>
    /// <param name="result"></param>
    public Spdx22Metadata SetMetadata(ParserResults result)
    {
        // TODO: Eventually this return type should be changed to SpdxMetadata to be consistent with naming.
        var metadata = new Spdx22Metadata();
        var spdxDocumentElement = (SpdxDocument?)result.FormatEnforcedSPDX3Result.Graph.FirstOrDefault(element => element.Type == "SpdxDocument");

        if (spdxDocumentElement == null)
        {
            return metadata;
        }

        if (spdxDocumentElement.NamespaceMap != null && spdxDocumentElement.NamespaceMap.TryGetValue("sbom", out var namespaceUri))
        {
            metadata.DocumentNamespace = new Uri(namespaceUri);
        }

        metadata.Name = spdxDocumentElement.Name;
        metadata.SpdxId = spdxDocumentElement.SpdxId;
        metadata.DocumentDescribes = spdxDocumentElement.RootElement;

        var dataLicenseSpdxId = spdxDocumentElement.DataLicense;
        var spdxDataLicenseElement = result.FormatEnforcedSPDX3Result.Graph.
            FirstOrDefault(element => element.SpdxId == dataLicenseSpdxId) as AnyLicenseInfo;
        metadata.DataLicense = spdxDataLicenseElement?.Name;

        var spdxCreationInfoElement = (CreationInfo?)result.FormatEnforcedSPDX3Result.Graph.
            Where(element => element.Type == nameof(CreationInfo)).
            FirstOrDefault(element => ((CreationInfo)element).Id == spdxDocumentElement.CreationInfoDetails);

        var creators = spdxCreationInfoElement?.CreatedBy
            .Select(createdBy => result.FormatEnforcedSPDX3Result.Graph.
            FirstOrDefault(element => element.SpdxId == createdBy) as Organization)
            .Where(spdxOrganizationElement => spdxOrganizationElement != null)
            .Select(spdxOrganizationElement => spdxOrganizationElement?.Name)
            .ToList() ?? [];

        creators.AddRange(spdxCreationInfoElement?.CreatedUsing
            .Select(createdBy => result.FormatEnforcedSPDX3Result.Graph.
            FirstOrDefault(element => element.SpdxId == createdBy) as Tool)
            .Where(spdxToolElement => spdxToolElement != null)
            .Select(spdxToolElement => spdxToolElement?.Name) ?? []);

        var createdDate = DateTime.MinValue;
        DateTime.TryParse(spdxCreationInfoElement?.Created, out createdDate);

        metadata.CreationInfo = new MetadataCreationInfo
        {
            Created = createdDate,
            Creators = creators,
        };

        metadata.SpdxVersion = spdxCreationInfoElement?.SpecVersion;

        return metadata;
    }
}
