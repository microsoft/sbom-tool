// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;
using SPDXConstants = Microsoft.Sbom.Parsers.Spdx30SbomParser.Constants;

namespace Microsoft.Sbom.Parser;

#nullable enable
/// <summary>
/// A parser for SPDX 3.0 SBOMs.
/// </summary>
/// <remarks>
/// This class is not Thread-safe since the stream and JsonReaders assume a single forward-only reader.
/// Because of the use of recursion in <see cref="LargeJsonParser30"/>, this class is also not suitable for parsing deeply nested json objects.
/// </remarks>
public class SPDX30Parser : ISbomParser
{
    public const string ContextProperty = SPDXConstants.SPDXContextHeaderName;
    public const string GraphProperty = SPDXConstants.SPDXGraphHeaderName;
    public static readonly IReadOnlyCollection<string> RequiredFields = new List<string>
    {
        ContextProperty,
        GraphProperty,
    };

    public string? RequiredComplianceStandard;
    public IReadOnlyCollection<string>? EntitiesToEnforceComplianceStandardsFor;
    public Spdx22Metadata Metadata = new Spdx22Metadata();
    private readonly LargeJsonParser parser;
    private readonly IList<string> observedFieldNames = new List<string>();
    private readonly bool requiredFieldsCheck = true;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    private bool parsingComplete = false;
    private readonly ManifestInfo spdxManifestInfo = new()
    {
        Name = SPDXConstants.SPDXName,
        Version = SPDXConstants.SPDXVersion,
    };

    private readonly IReadOnlyCollection<string> entitiesWithDifferentNTIARequirements = new List<string>
    {
        "SpdxDocument",
        "File",
        "Package",
    };

    public SPDX30Parser(
        Stream stream,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
    {
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions
        {
            Converters = { new ElementSerializer(), new JsonStringEnumConverter() },
        };

        var handlers = new Dictionary<string, PropertyHandler>
        {
            { ContextProperty, new PropertyHandler<string>(ParameterType.Array) },
            { GraphProperty, new PropertyHandler<JsonNode>(ParameterType.Array) },
        };

        if (!string.IsNullOrEmpty(this.RequiredComplianceStandard))
        {
            if (!Enum.TryParse<ComplianceStandard>(this.RequiredComplianceStandard, true, out var complianceStandardAsEnum))
            {
                throw new ParserException($"{this.RequiredComplianceStandard} compliance standard is not supported.");
            }
            else
            {
                switch (complianceStandardAsEnum)
                {
                    case ComplianceStandard.NTIA:
                        this.EntitiesToEnforceComplianceStandardsFor = this.entitiesWithDifferentNTIARequirements;
                        break;
                    default:
                        throw new ParserException($"{this.RequiredComplianceStandard} compliance standard is not supported.");
                }
            }
        }
        else
        {
            Console.WriteLine("No required compliance standard.");
        }

        if (bufferSize is null)
        {
            this.parser = new LargeJsonParser(stream, handlers, this.jsonSerializerOptions);
        }
        else
        {
            this.parser = new LargeJsonParser(stream, handlers, this.jsonSerializerOptions, bufferSize.Value);
        }
    }

    /// <summary>
    /// Return the <see cref="ParserStateResult"/> result from the parser.
    /// </summary>
    /// <returns>null if parsing is complete, otherwise a <see cref="ParserStateResult"/> representing the field which was visited. These results represent the root level fields of a json object.
    /// If the field is an array the result will be an IEnumerable which you MUST fully enumerate before calling Next() again.
    /// </returns>
    /// <exception cref="ParserException"></exception>
    public ParserStateResult? Next()
    {
        ParserStateResult? result = null;
        do
        {
            result = parser.Next();

            if (result is not null && result.Result is not null)
            {
                var fieldName = result.FieldName;
                this.observedFieldNames.Add(fieldName);
                var jsonElements = result.Result as IEnumerable<object>;
                var jsonList = jsonElements?.ToList();
                switch (fieldName)
                {
                    case ContextProperty:
                        var contextResult = new ContextsResult(result, jsonList);
                        ValidateContext(contextResult);
                        result = contextResult;
                        break;
                    case GraphProperty:
                        var elementsResult = ConvertToElements(jsonList, ref result, this.RequiredComplianceStandard, this.EntitiesToEnforceComplianceStandardsFor);
                        this.Metadata = this.SetMetadata(elementsResult);
                        result = elementsResult;
                        break;
                    default:
                        throw new InvalidDataException($"Explicit field {result.FieldName} is unhandled.");
                }

                return result;
            }
        } while (result is not null);

        if (this.requiredFieldsCheck)
        {
            foreach (var requiredField in RequiredFields)
            {
                if (!this.observedFieldNames.Contains(requiredField))
                {
                    throw new ParserException($"Required field {requiredField} was not found in the SPDX file");
                }
            }
        }

        this.parsingComplete = true;

        return null;
    }

    private void ValidateContext(ContextsResult result)
    {
        if (result.Contexts == null || !result.Contexts.Any() || result.Contexts.Count() > 1)
        {
            throw new ParserException($"The context property is either empty or has more than one string.");
        }
    }

    /// <summary>
    /// Converts JSON objects to SPDX elements.
    /// </summary>
    /// <param name="jsonList"></param>
    /// <returns></returns>
    public ElementsResult ConvertToElements(List<object>? jsonList, ref ParserStateResult? result, string? requiredComplianceStandard, IReadOnlyCollection<string>? entitiesWithDifferentNTIARequirements)
    {
        var elementsResult = new ElementsResult(result);
        var elementsList = new List<Element>();
        var elementsSpdxIdList = new HashSet<string>();
        var filesList = new List<Parsers.Spdx30SbomParser.Entities.File>();

        if (jsonList is null)
        {
            elementsResult.FilesCount = 0;
            elementsResult.PackagesCount = 0;
            elementsResult.ReferencesCount = 0;
            elementsResult.RelationshipsCount = 0;
            elementsResult.Elements = elementsList;
            return elementsResult;
        }

        var complianceStandardAsEnum = ComplianceStandard.None;
        if (!string.IsNullOrEmpty(this.RequiredComplianceStandard))
        {
            if (!Enum.TryParse(this.RequiredComplianceStandard, true, out complianceStandardAsEnum))
            {
                throw new ParserException($"{this.RequiredComplianceStandard} compliance standard is not supported.");
            }
            else
            {
                switch (complianceStandardAsEnum)
                {
                    case ComplianceStandard.NTIA:
                        this.EntitiesToEnforceComplianceStandardsFor = this.entitiesWithDifferentNTIARequirements;
                        break;
                    default:
                        throw new ParserException($"{this.RequiredComplianceStandard} compliance standard is not supported.");
                }
            }
        }
        else
        {
            Console.WriteLine("No required compliance standard.");
        }

        foreach (JsonObject jsonObject in jsonList)
        {
            if (jsonObject == null || !jsonObject.Any())
            {
                continue;
            }

            var entityType = GetEntityType(jsonObject, complianceStandardAsEnum);

            object? deserializedObject = null;
            try
            {
                deserializedObject = JsonSerializer.Deserialize(jsonObject.ToString(), entityType, jsonSerializerOptions);
            }
            catch (Exception e)
            {
                throw new ParserException(e.Message);
            }

            if (deserializedObject != null)
            {
                var deserializedElement = (Element)deserializedObject;

                // Deduplication of elements by checking SPDX ID
                var spdxId = deserializedElement.SpdxId;
                if (!elementsSpdxIdList.TryGetValue(spdxId, out _))
                {
                    elementsList.Add(deserializedElement);
                    elementsSpdxIdList.Add(spdxId);
                }
                else
                {
                    Console.WriteLine($"Duplicate element with SPDX ID {spdxId} found. Skipping.");
                }

                switch (entityType?.Name)
                {
                    case string name when name.Contains("File"):
                        filesList.Add((Parsers.Spdx30SbomParser.Entities.File)deserializedElement);
                        elementsResult.FilesCount += 1;
                        break;
                    case string name when name.Contains("Package"):
                        elementsResult.PackagesCount += 1;
                        break;
                    case string name when name.Contains("ExternalMap"):
                        elementsResult.ReferencesCount += 1;
                        break;
                    case string name when name.Contains("Relationship"):
                        elementsResult.RelationshipsCount += 1;
                        break;
                    default:
                        Console.WriteLine($"Unrecognized entity type: {entityType?.Name}");
                        break;
                }
            }
        }

        // Validate if elements meet required compliance standards
        switch (complianceStandardAsEnum)
        {
            case ComplianceStandard.NTIA:
                ValidateNTIARequirements(elementsList);
                break;
        }

        elementsResult.Elements = elementsList;
        elementsResult.Files = filesList;

        return elementsResult;
    }

    public Type GetEntityType(JsonObject jsonObject, ComplianceStandard? requiredComplianceStandard)
    {
        var assembly = typeof(Element).Assembly;
        var typeFromSbom = jsonObject["type"]?.ToString();
        var entityType = typeFromSbom;

        // For these special cases, remove the prefix from the type.
        switch (typeFromSbom)
        {
            case "software_File":
                entityType = "File";
                break;
            case "software_Package":
                entityType = "Package";
                break;
        }

        // If the entity type is in the list of entities that require different NTIA requirements, then add the NTIA prefix.
        switch (requiredComplianceStandard)
        {
            case ComplianceStandard.NTIA:
                if (this.EntitiesToEnforceComplianceStandardsFor?.Contains(entityType) == true)
                {
                    entityType = "NTIA" + entityType;
                }

                break;
        }

        var type = assembly.GetType($"Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.{entityType}") ?? throw new ParserException($"Type \"{typeFromSbom} on {jsonObject} is invalid.");

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
    public SpdxMetadata SetMetadata(ElementsResult result)
    {
        var metadata = new SpdxMetadata();
        var spdxDocumentElement = (SpdxDocument?)result.Elements.FirstOrDefault(element => element.Type == "SpdxDocument");

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
        var spdxDataLicenseElement = result.Elements.
            FirstOrDefault(element => element.SpdxId == dataLicenseSpdxId) as AnyLicenseInfo;
        metadata.DataLicense = spdxDataLicenseElement?.Name;

        var spdxCreationInfoElement = (CreationInfo?)result.Elements.
            Where(element => element.Type == nameof(CreationInfo)).
            FirstOrDefault(element => ((CreationInfo)element).Id == spdxDocumentElement.CreationInfoDetails);

        var creators = spdxCreationInfoElement?.CreatedBy
            .Select(createdBy => result.Elements.
            FirstOrDefault(element => element.SpdxId == createdBy) as Organization)
            .Where(spdxOrganizationElement => spdxOrganizationElement != null)
            .Select(spdxOrganizationElement => spdxOrganizationElement?.Name)
            .ToList() ?? [];

        creators.AddRange(spdxCreationInfoElement?.CreatedUsing
            .Select(createdBy => result.Elements.
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

    public Spdx22Metadata GetMetadata()
    {
        if (!this.parsingComplete)
        {
            throw new ParserException($"{nameof(this.GetMetadata)} can only be called after Parsing is complete to ensure that a whole object is returned.");
        }

        // TODO: Eventually this return type should be changed to SpdxMetadata to be consistent with naming.
        return this.Metadata;
    }

    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { this.spdxManifestInfo };
}
