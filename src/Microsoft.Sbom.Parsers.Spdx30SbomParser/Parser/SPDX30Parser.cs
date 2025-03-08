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
using SPDX30Constants = Microsoft.Sbom.Parsers.Spdx30SbomParser.Constants;

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
    internal ComplianceStandard? RequiredComplianceStandard;

    private static readonly IReadOnlyCollection<string> RequiredFields = new List<string>
    {
        SPDX30Constants.SPDXContextHeaderName,
        SPDX30Constants.SPDXGraphHeaderName,
    };

    private static readonly IReadOnlyCollection<string> EntitiesWithDifferentNTIARequirements = new List<string>
    {
        "SpdxDocument",
        "File",
    };

    private IReadOnlyCollection<string>? entititesRequiringDeserializationWithNTIA;
    private SpdxMetadata metadata = new SpdxMetadata();
    private readonly LargeJsonParser parser;
    private readonly IList<string> observedFieldNames = new List<string>();
    private readonly bool requiredFieldsCheck = true;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    private bool parsingComplete = false;

    public SPDX30Parser(
        Stream stream,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
    {
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions
        {
            Converters =
            {
                new ElementSerializer(),
                new JsonStringEnumConverter()
            },
        };

        var handlers = new Dictionary<string, PropertyHandler>
        {
            { SPDX30Constants.SPDXContextHeaderName, new PropertyHandler<string>(ParameterType.Array) },
            { SPDX30Constants.SPDXGraphHeaderName, new PropertyHandler<JsonNode>(ParameterType.Array) },
        };

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

            if (result?.Result is not null)
            {
                var fieldName = result.FieldName;
                this.observedFieldNames.Add(fieldName);
                var jsonElements = result.Result as IEnumerable<object>;
                var jsonList = jsonElements?.ToList();
                switch (fieldName)
                {
                    case SPDX30Constants.SPDXContextHeaderName:
                        result = ConvertToContexts(jsonList, result);
                        break;
                    case SPDX30Constants.SPDXGraphHeaderName:
                        var elementsResult = ConvertToElements(jsonList, result);
                        this.metadata = SetMetadata(elementsResult);
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

    public SpdxMetadata GetMetadata()
    {
        if (!this.parsingComplete)
        {
            throw new ParserException($"{nameof(this.GetMetadata)} can only be called after Parsing is complete to ensure that a whole object is returned.");
        }

        return this.metadata;
    }

    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { SPDX30Constants.SPDX30ManifestInfo };

    public void SetComplianceStandard(string? complianceStandardFromCli)
    {
        if (string.IsNullOrEmpty(complianceStandardFromCli))
        {
            // If no compliance standard is set, then we don't need to enforce any compliance standards.
            return;
        }
        else if (Enum.TryParse<ComplianceStandard>(complianceStandardFromCli, true, out var complianceStandardAsEnum))
        {
            switch (complianceStandardAsEnum)
            {
                case ComplianceStandard.NTIA:
                    RequiredComplianceStandard = complianceStandardAsEnum;
                    entititesRequiringDeserializationWithNTIA = EntitiesWithDifferentNTIARequirements;
                    break;
                default:
                    break;
            }
        }
        else
        {
            throw new ParserException($"Unable to use the given compliance standard {complianceStandardFromCli} to parse the SBOM.");
        }
    }

    private ContextsResult ConvertToContexts(List<object>? jsonList, ParserStateResult? result)
    {
        if (jsonList != null && jsonList.All(e => e is string))
        {
            var contextsResult = new ContextsResult(result, jsonList.Cast<string>().ToList());
            ValidateContext(contextsResult);
            return contextsResult;
        }
        else
        {
            throw new InvalidDataException("The context property must be a list of strings.");
        }
    }

    private void ValidateContext(ContextsResult result)
    {
        if (result.Contexts == null || !result.Contexts.Any() || result.Contexts.Count() > 1)
        {
            throw new ParserException($"The context property is invalid. It should only have one string.");
        }
    }

    /// <summary>
    /// Converts JSON objects to SPDX elements.
    /// </summary>
    /// <param name="jsonList"></param>
    /// <returns></returns>
    private ElementsResult ConvertToElements(List<object>? jsonList, ParserStateResult? result)
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

        foreach (JsonObject jsonObject in jsonList)
        {
            var deserializedElement = ParseJsonObject(jsonObject, RequiredComplianceStandard);

            if (deserializedElement is not null)
            {
                if (IsUniqueElement(deserializedElement.SpdxId, elementsSpdxIdList))
                {
                    elementsList.Add(deserializedElement);
                }

                AggregateElementsBasedOnType(deserializedElement, elementsResult, filesList);
            }
        }

        ValidateElementsBasedOnComplianceStandard(RequiredComplianceStandard, elementsList);

        elementsResult.Elements = elementsList;
        elementsResult.Files = filesList;

        return elementsResult;
    }

    private Type GetEntityType(JsonObject jsonObject, ComplianceStandard? requiredComplianceStandard)
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
        // This will allow for deserialization based on compliance standard so that we can detect if certain required fields are missing.
        switch (requiredComplianceStandard)
        {
            case ComplianceStandard.NTIA:
                if (this.entititesRequiringDeserializationWithNTIA?.Contains(entityType) == true)
                {
                    entityType = "NTIA" + entityType;
                }

                break;
        }

        var type = assembly.GetType($"Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.{entityType}") ?? throw new ParserException($"Type \"{typeFromSbom} on {jsonObject} is invalid.");

        return type;
    }

    private void ValidateNTIARequirements(List<Element> elementsList)
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
    private void ValidateSbomDocCreationForNTIA(List<Element> elementsList)
    {
        var spdxDocumentElements = elementsList.Where(element => element is SpdxDocument).ToList();
        if (spdxDocumentElements.Count != 1)
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
    private void ValidateSbomFilesForNTIA(List<Element> elementsList)
    {
        var fileElements = elementsList.Where(element => element is Parsers.Spdx30SbomParser.Entities.File);
        foreach (var fileElement in fileElements)
        {
            var fileSpdxId = fileElement.SpdxId;

            var fileHasSha256Hash = fileElement.VerifiedUsing.
                Any(packageVerificationCode => packageVerificationCode.Algorithm == HashAlgorithm.sha256);

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
    private void ValidateSbomPackagesForNTIA(List<Element> elementsList)
    {
        var packageElements = elementsList.Where(element => element is Package);
        foreach (var packageElement in packageElements)
        {
            var packageSpdxId = packageElement.SpdxId;

            var packageHasSha256Hash = packageElement.VerifiedUsing?.
                Any(packageVerificationCode => packageVerificationCode.Algorithm == HashAlgorithm.sha256);

            if (packageHasSha256Hash is null || packageHasSha256Hash == false)
            {
                throw new ParserException($"SBOM document is not NTIA compliant because package with SPDX ID {packageSpdxId} does not have a SHA256 hash.");
            }
        }
    }

    /// <summary>
    /// Sets metadata based on parsed SBOM elements.
    /// </summary>
    /// <param name="result"></param>
    private SpdxMetadata SetMetadata(ElementsResult result)
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

    /// <summary>
    /// Validate if elements meet required compliance standards
    /// </summary>
    /// <param name="complianceStandardAsEnum"></param>
    /// <param name="elementsList"></param>
    private void ValidateElementsBasedOnComplianceStandard(ComplianceStandard? complianceStandardAsEnum, List<Element> elementsList)
    {
        switch (complianceStandardAsEnum)
        {
            case ComplianceStandard.NTIA:
                ValidateNTIARequirements(elementsList);
                break;
            default:
                break;
        }
    }

    private Element? ParseJsonObject(JsonObject jsonObject, ComplianceStandard? complianceStandardAsEnum)
    {
        if (jsonObject is null || !jsonObject.Any())
        {
            return null;
        }
        else
        {
            var entityType = GetEntityType(jsonObject, complianceStandardAsEnum);

            object? deserializedObject = null;
            try
            {
                deserializedObject = JsonSerializer.Deserialize(jsonObject.ToString(), entityType, jsonSerializerOptions);
            }
            catch (Exception e)
            {
                switch (complianceStandardAsEnum)
                {
                    case ComplianceStandard.NTIA:
                        throw new ParserException($"SBOM document is not NTIA compliant because {jsonObject} does not have all the required fields for NTIA compliance.");
                    default:
                        throw new ParserException(e.Message);
                }
            }

            var deserializedElement = (Element?)deserializedObject;

            return deserializedElement;
        }
    }

    /// <summary>
    /// Handle deduplication of elements by checking SPDX ID
    /// </summary>
    /// <param name="spdxId"></param>
    /// <param name="elementsList"></param>
    /// <param name="elementsSpdxIdList"></param>
    /// <returns></returns>
    private bool IsUniqueElement(string spdxId, HashSet<string> elementsSpdxIdList)
    {
        if (!elementsSpdxIdList.TryGetValue(spdxId, out _))
        {
            elementsSpdxIdList.Add(spdxId);
            return true;
        }
        else
        {
            return false;
        }
    }

    private void AggregateElementsBasedOnType(Element deserializedElement, ElementsResult elementsResult, List<Parsers.Spdx30SbomParser.Entities.File> filesList)
    {
        var entityType = deserializedElement.GetType();

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
                break;
        }
    }
}
