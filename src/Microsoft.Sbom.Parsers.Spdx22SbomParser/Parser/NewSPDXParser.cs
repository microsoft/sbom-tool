// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using JsonAsynchronousNodeKit;
using JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

// TODO: New Name
#nullable enable
public class NewSPDXParser : ISbomParser
{
    public const string FilesProperty = "files";
    public const string ReferenceProperty = "externalDocumentRefs";
    public const string PackagesProperty = "packages";
    public const string RelationshipsProperty = "relationships";

    private readonly LargeJsonParser parser;

    private readonly IDictionary<string, object?> metadata = new Dictionary<string, object?>();
    private static readonly IReadOnlyCollection<string> RequiredFields = new List<string>
    {
        FilesProperty,
        PackagesProperty,
        RelationshipsProperty,
    };

    private readonly IList<string> observedFieldNames = new List<string>();
    private readonly bool requiredFieldsCheck = true;
    private readonly JsonSerializerOptions jsonSerializerOptions;

    [Obsolete("For tests only")]
    internal NewSPDXParser(
        Stream stream,
        bool requirementsCheck,
        IEnumerable<string>? skippedProperties = null,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
        : this(stream, skippedProperties, jsonSerializerOptions, bufferSize)
    {
        this.requiredFieldsCheck = requirementsCheck;
    }

    public NewSPDXParser(
        Stream stream,
        IEnumerable<string>? skippedProperties = null,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
    {
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions();
        var handlers = new Dictionary<string, PropertyHandler>
        {
            { ReferenceProperty, new PropertyHandler<SpdxExternalDocumentReference>(ParameterType.Array) },
            { PackagesProperty, new PropertyHandler<SPDXPackage>(ParameterType.Array) },
            { RelationshipsProperty, new PropertyHandler<SPDXRelationship>(ParameterType.Array) },
            { FilesProperty, new PropertyHandler<SPDXFile>(ParameterType.Array) },
        };

        if (skippedProperties is not null)
        {
            foreach (var skippedProperty in skippedProperties)
            {
                handlers[skippedProperty] = new PropertyHandler<JsonNode>(ParameterType.Skip);
            }
        }

        if (bufferSize is null)
        {
            this.parser = new LargeJsonParser(stream, handlers, jsonSerializerOptions);
        }
        else
        {
            this.parser = new LargeJsonParser(stream, handlers, jsonSerializerOptions, bufferSize.Value);
        }
    }

    public ParserStateResult? Next()
    {
        // TODO: what happens if we call Next after already reaching the end?
        ParserStateResult? result;
        do
        {
            result = this.parser.Next();
            if (result is not null)
            {
                this.observedFieldNames.Add(result.FieldName);
                if (result.Result is not null)
                {
                    if (!result.ExplicitField)
                    {
                        var r = result.Result;
                        if (result.Result is IEnumerable<object> enumResult)
                        {
                            r = enumResult.ToList();
                        }

                        this.metadata.TryAdd(result.FieldName, r);
                    }
                    else
                    {
                        switch (result.FieldName)
                        {
                            case FilesProperty:
                                result = new FilesResult(result);
                                break;
                            case PackagesProperty:
                                result = new PackagesResult(result);
                                break;
                            case RelationshipsProperty:
                                result = new RelationshipsResult(result);
                                break;
                            case ReferenceProperty:
                                result = new ExternalDocumentReferencesResult(result);
                                break;
                        }
                    }

                    return result;
                }
            }
        }
        while (result is not null);

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

        return null;
    }

    // TODO: Only allow calling this after everyting has been parsed?
    public Spdx22Metadata GetMetadata()
    {
        var spdxMetadata = new Spdx22Metadata();
        foreach (var kvp in this.metadata)
        {
            switch (kvp.Key)
            {
                case Constants.SPDXVersionHeaderName:
                    spdxMetadata.SpdxVersion = this.Coerse<string>(kvp.Key, kvp.Value);
                    break;
                case Constants.DataLicenseHeaderName:
                    spdxMetadata.DataLicense = this.Coerse<string>(kvp.Key, kvp.Value);
                    break;
                case Constants.DocumentNameHeaderName:
                    spdxMetadata.Name = this.Coerse<string>(kvp.Key, kvp.Value);
                    break;
                case Constants.DocumentNamespaceHeaderName:
                    spdxMetadata.DocumentNamespace = new Uri(this.Coerse<string>(kvp.Key, kvp.Value));
                    break;
                case Constants.CreationInfoHeaderName:
                    spdxMetadata.CreationInfo = this.Coerse<MetadataCreationInfo>(kvp.Key, kvp.Value);
                    break;
                case Constants.DocumentDescribesHeaderName:
                    spdxMetadata.DocumentDescribes = ((List<object>)kvp.Value!).Cast<string>();
                    break;
                case Constants.SPDXIDHeaderName:
                    spdxMetadata.SpdxId = this.Coerse<string>(kvp.Key, kvp.Value);
                    break;
                default:
                    break;
            }
        }

        return spdxMetadata;
    }

    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { spdxManifestInfo };

    private T Coerse<T>(string name, object? value)
    {
        if (value is T t)
        {
            return t;
        }
        else if (value is JsonNode jsonNode)
        {
            var deserialized = JsonSerializer.Deserialize<T>(jsonNode, this.jsonSerializerOptions);
            if (deserialized is not null)
            {
                return deserialized;
            }
            else
            {
                throw new ParserException($"Failed to deserialize {name} to {typeof(T).Name}");
            }
        }

        throw new ParserException($"Expected type {typeof(T).Name} for {name} but got {value?.GetType().Name ?? "null"}");
    }

    private readonly ManifestInfo spdxManifestInfo = new()
    {
        Name = Constants.SPDXName,
        Version = Constants.SPDXVersion
    };
}
