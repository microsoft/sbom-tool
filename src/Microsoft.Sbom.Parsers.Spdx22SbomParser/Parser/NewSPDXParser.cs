// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using JsonStreaming;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;

namespace Microsoft.Sbom.Parser;

#nullable enable
public abstract class NewSPDXParser
{
    public const string FilesProperty = "files";
    private const string ReferenceProperty = "externalDocumentRefs";
    private const string PackagesProperty = "packages";
    private const string RelationshipsProperty = "relationships";

    private readonly LargeJsonParser parser;

    private readonly IDictionary<string, object?> metadata = new Dictionary<string, object?>();
    private static readonly IReadOnlyCollection<string> RequiredFields = new List<string>
    {
        FilesProperty,
        PackagesProperty,
        RelationshipsProperty,
    };

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

    public async Task ParseAsync(CancellationToken cancellationToken)
    {
        JsonStreaming.ParserStateResult? result = null;
        var observedFieldNames = new List<string>();
        do
        {
            result = this.parser.Next();
            if (result is not null)
            {
                observedFieldNames.Add(result.FieldName);
                if (result.Result is not null)
                {
                    switch (result.FieldName)
                    {
                        case ReferenceProperty:
                            if (result.Result is not IEnumerable<object> spdxReferences)
                            {
                                throw new InvalidDataException("Didn't match expected types");
                            }

                            var references = spdxReferences.Select(r => ((SpdxExternalDocumentReference)r).ToSbomReference());
                            await this.HandleReferencesAsync(references, cancellationToken);
                            break;
                        case PackagesProperty:
                            if (result.Result is not IEnumerable<object> spdxPackages)
                            {
                                throw new InvalidDataException("Didn't match expected types");
                            }

                            var packages = spdxPackages.Select(p => ((SPDXPackage)p).ToSbomPackage());
                            await this.HandlePackagesAsync(packages, cancellationToken);
                            break;
                        case RelationshipsProperty:
                            if (result.Result is not IEnumerable<object> spdxRelationships)
                            {
                                throw new InvalidDataException("Didn't match expected types");
                            }

                            var relationships = spdxRelationships.Select(r => ((SPDXRelationship)r).ToSbomRelationship());
                            await this.HandleRelationshipsAsync(relationships, cancellationToken);
                            break;
                        case FilesProperty:
                            if (result.Result is not IEnumerable<object> spdxFiles)
                            {
                                throw new InvalidDataException("Didn't match expected types");
                            }

                            var files = spdxFiles.Select(f => ((SPDXFile)f).ToSbomFile());
                            await this.HandleFilesAsync(files, cancellationToken);
                            break;
                        default:
                            var r = result.Result;
                            if (result.Result is IEnumerable<JsonNode> enumResult)
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
                if (!observedFieldNames.Contains(requiredField))
                {
                    throw new ParserException($"Required field {requiredField} was not found in the SPDX file");
                }
            }
        }
    }

    public abstract Task HandleFilesAsync(IEnumerable<SbomFile> files, CancellationToken cancellationToken);

    public abstract Task HandleReferencesAsync(IEnumerable<SBOMReference> references, CancellationToken cancellationToken);

    public abstract Task HandleRelationshipsAsync(IEnumerable<SBOMRelationship> relationships, CancellationToken cancellationToken);

    public abstract Task HandlePackagesAsync(IEnumerable<SbomPackage> packages, CancellationToken cancellationToken);
}
