// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Conformance;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Conformance.Interfaces;
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
    private static readonly IReadOnlyCollection<string> RequiredFields = new List<string>
    {
        Constants.SPDXContextHeaderName,
        Constants.SPDXGraphHeaderName,
    };

    private SpdxMetadata metadata = new SpdxMetadata();
    private readonly LargeJsonParser parser;
    private readonly IList<string> observedFieldNames = new List<string>();
    private readonly bool requiredFieldsCheck = true;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    private bool parsingComplete = false;
    private IConformanceEnforcer conformanceEnforcer;

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
            { Constants.SPDXContextHeaderName, new PropertyHandler<string>(ParameterType.Array) },
            { Constants.SPDXGraphHeaderName, new PropertyHandler<JsonNode>(ParameterType.Array) },
        };

        if (bufferSize is null)
        {
            this.parser = new LargeJsonParser(stream, handlers, this.jsonSerializerOptions);
        }
        else
        {
            this.parser = new LargeJsonParser(stream, handlers, this.jsonSerializerOptions, bufferSize.Value);
        }

        // Set default to enforce None conformance
        this.conformanceEnforcer = new NoneConformanceEnforcer();
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
                    case Constants.SPDXContextHeaderName:
                        result = ConvertToContexts(jsonList, result);
                        break;
                    case Constants.SPDXGraphHeaderName:
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

    public void EnforceConformance(ConformanceType conformance)
    {
        this.conformanceEnforcer = ConformanceEnforcerFactory.Create(conformance);
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
            throw new ParserException("The context property is invalid. It should only have one string.");
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

        if (jsonList is null)
        {
            return elementsResult;
        }

        foreach (JsonObject jsonObject in jsonList)
        {
            var deserializedElement = ParseJsonObject(jsonObject, elementsResult);

            if (deserializedElement is not null)
            {
                if (IsUniqueElement(deserializedElement.SpdxId, elementsResult.ElementsSpdxIdList))
                {
                    elementsResult.Elements.Add(deserializedElement);
                }

                AggregateElementsBasedOnType(deserializedElement, elementsResult);
            }
        }

        conformanceEnforcer.AddInvalidElements(elementsResult);

        return elementsResult;
    }

    private Type GetEntityType(JsonObject jsonObject, ConformanceType requiredConformance)
    {
        var assembly = typeof(Element).Assembly;
        var typeFromSbom = jsonObject["type"]?.ToString();
        var entityType = typeFromSbom;

        // If the entity type is in the list of entities that require different NTIAMin requirements, then add the NTIAMin prefix.
        // This will allow for deserialization based on conformance so that we can detect if certain required fields are missing.
        entityType = conformanceEnforcer.GetConformanceEntityType(entityType);

        var type = assembly.GetType($"Microsoft.Sbom.Common.Spdx30Entities.{entityType}") ?? throw new ParserException($"Type \"{typeFromSbom} on {jsonObject} is invalid.");

        return type;
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

    private Element? ParseJsonObject(JsonObject jsonObject, ElementsResult elementsResult)
    {
        if (jsonObject is null || !jsonObject.Any())
        {
            return null;
        }
        else
        {
            var entityType = GetEntityType(jsonObject, conformanceEnforcer.Conformance);

            object? deserializedObject = null;
            var jsonObjectAsString = jsonObject.ToString();
            try
            {
                deserializedObject = JsonSerializer.Deserialize(jsonObjectAsString, entityType, jsonSerializerOptions);
            }
            catch (Exception e)
            {
                conformanceEnforcer.AddInvalidElementsIfDeserializationFails(jsonObjectAsString, jsonSerializerOptions, elementsResult.InvalidConformanceElements, e);
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

    private void AggregateElementsBasedOnType(
        Element deserializedElement,
        ElementsResult elementsResult)
    {
        var entityType = deserializedElement.GetType();

        switch (entityType?.Name)
        {
            case string name when name.Contains("File"):
                elementsResult.Files.Add((Common.Spdx30Entities.File)deserializedElement);
                elementsResult.FilesCount += 1;
                break;
            case string name when name.Contains("Package"):
                elementsResult.Packages.Add((Package)deserializedElement);
                elementsResult.PackagesCount += 1;
                break;
            case string name when name.Contains("ExternalMap"):
                elementsResult.ReferencesCount += 1;
                break;
            case string name when name.Contains("Relationship"):
                elementsResult.RelationshipsCount += 1;
                break;
            case string name when name.Contains("SpdxDocument"):
                elementsResult.SpdxDocuments.Add((SpdxDocument)deserializedElement);
                break;
            case string name when name.Contains("CreationInfo"):
                elementsResult.CreationInfos.Add((CreationInfo)deserializedElement);
                break;
            default:
                break;
        }
    }
}
