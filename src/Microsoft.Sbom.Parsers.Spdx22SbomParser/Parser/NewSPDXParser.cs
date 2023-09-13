// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using JsonStreaming;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

#nullable enable
public class NewSPDXParser
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
                    if (result.explicitField)
                    {
                        return result;
                    }
                    else
                    {
                        var r = result.Result;
                        if (result.Result is IEnumerable<object> enumResult)
                        {
                            r = enumResult.ToList();
                        }

                        this.metadata.Add(result.FieldName, r);
                        break;
                    }
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
                    if (kvp.Value is string version)
                    {
                        spdxMetadata.SpdxVersion = version;
                        break;
                    }
                    else
                    {
                        throw new ParserException($"SPDX version is not a string");
                    }

                case Constants.DataLicenseHeaderName:
                    if (kvp.Value is string dataLicense)
                    {
                        spdxMetadata.DataLicense = dataLicense;
                        break;
                    }
                    else
                    {
                        throw new ParserException($"Data license is not a string");
                    }

                case Constants.DocumentNameHeaderName:
                    if (kvp.Value is string documentName)
                    {
                        spdxMetadata.Name = documentName;
                        break;
                    }
                    else
                    {
                        throw new ParserException($"DocumentName is not a string");
                    }

                case Constants.DocumentNamespaceHeaderName:
                    if (kvp.Value is string documentNamespace)
                    {
                        spdxMetadata.DocumentNamespace = new Uri(documentNamespace);
                        break;
                    }
                    else
                    {
                        throw new ParserException($"DocumentNamespace is not a string");
                    }

                case Constants.CreationInfoHeaderName:
                    var parser = new CreationInfoParser(stream);
spdxMetadata.CreationInfo = parser.GetCreationInfo(ref buffer, ref reader);
                    break;
                case Constants.DocumentDescribesHeaderName:
                    spdxMetadata.DocumentDescribes = ParserUtils.ParseListOfStrings(stream, ref reader, ref buffer);
                    break;
                case Constants.SPDXIDHeaderName:
                    spdxMetadata.SpdxId = nextTokenString;
                    break;
                default:
                    throw new ParserException($"Unknown metadata property {currentRootPropertyName} found while parsing metadata.");
            }
        }

        return spdxMetadata;
    }
}
