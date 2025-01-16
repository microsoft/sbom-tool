// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using SPDXConstants = Microsoft.Sbom.Parsers.Spdx22SbomParser.Constants;

namespace Microsoft.Sbom.Parser;

#nullable enable
/// <summary>
/// A parser for SPDX 2.2 SBOMs.
/// </summary>
/// <remarks>
/// This class is not Thread-safe since the stream and JsonReaders assume a single forward-only reader.
/// Because of the use of recursion in <see cref="LargeJsonParser"/>, this class is also not suitable for parsing deeply nested json objects.
/// </remarks>
public class SPDXParser : ISbomParser
{
    public const string FilesProperty = SPDXConstants.FilesArrayHeaderName;
    public const string ReferenceProperty = SPDXConstants.ExternalDocumentRefArrayHeaderName;
    public const string PackagesProperty = SPDXConstants.PackagesArrayHeaderName;
    public const string RelationshipsProperty = SPDXConstants.RelationshipsArrayHeaderName;

    private static readonly IReadOnlyCollection<string> RequiredFields = new List<string>
    {
        FilesProperty,
        PackagesProperty,
        RelationshipsProperty,
    };

    private readonly LargeJsonParser parser;
    private readonly IDictionary<string, object?> metadata = new Dictionary<string, object?>();

    private readonly IList<string> observedFieldNames = new List<string>();
    private readonly bool requiredFieldsCheck = true;
    private readonly JsonSerializerOptions jsonSerializerOptions;

    private readonly ManifestInfo spdxManifestInfo = new()
    {
        Name = SPDXConstants.SPDXName,
        Version = SPDXConstants.SPDXVersion,
    };

    private bool parsingComplete = false;

    public SPDXParser(
        Stream stream,
        IEnumerable<string>? skippedProperties = null,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
    {
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };
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

    [Obsolete("For tests only")]
    internal SPDXParser(
        Stream stream,
        bool requirementsCheck,
        IEnumerable<string>? skippedProperties = null,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
        : this(stream, skippedProperties, jsonSerializerOptions, bufferSize)
    {
        this.requiredFieldsCheck = requirementsCheck;
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

                        _ = this.metadata.TryAdd(result.FieldName, r);
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
                            default:
                                throw new InvalidDataException($"Explicit field {result.FieldName} is unhandled.");
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

        this.parsingComplete = true;

        return null;
    }

    public SpdxMetadata GetMetadata()
    {
        if (!this.parsingComplete)
        {
            throw new ParserException($"{nameof(this.GetMetadata)} can only be called after Parsing is complete to ensure that a whole object is returned.");
        }

        var spdxMetadata = new SpdxMetadata();
        foreach (var kvp in this.metadata)
        {
            switch (kvp.Key)
            {
                case SPDXConstants.SPDXVersionHeaderName:
                    spdxMetadata.SpdxVersion = this.Coerce<string>(kvp.Key, kvp.Value);
                    break;
                case SPDXConstants.DataLicenseHeaderName:
                    spdxMetadata.DataLicense = this.Coerce<string>(kvp.Key, kvp.Value);
                    break;
                case SPDXConstants.DocumentNameHeaderName:
                    spdxMetadata.Name = this.Coerce<string>(kvp.Key, kvp.Value);
                    break;
                case SPDXConstants.DocumentNamespaceHeaderName:
                    spdxMetadata.DocumentNamespace = new Uri(this.Coerce<string>(kvp.Key, kvp.Value));
                    break;
                case SPDXConstants.CreationInfoHeaderName:
                    spdxMetadata.CreationInfo = this.Coerce<MetadataCreationInfo>(kvp.Key, kvp.Value);
                    break;
                case SPDXConstants.DocumentDescribesHeaderName:
                    spdxMetadata.DocumentDescribes = ((List<object>)kvp.Value!).Cast<string>();
                    break;
                case SPDXConstants.SPDXIDHeaderName:
                    spdxMetadata.SpdxId = this.Coerce<string>(kvp.Key, kvp.Value);
                    break;
                default:
                    break;
            }
        }

        return spdxMetadata;
    }

    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { this.spdxManifestInfo };

    private T Coerce<T>(string name, object? value)
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
}
