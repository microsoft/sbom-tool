// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
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

    public ComplianceStandard? RequiredComplianceStandard;
    public IReadOnlyCollection<string>? EntitiesToEnforceComplianceStandardsFor;
    public SpdxMetadata Metadata = new Spdx30Metadata();
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
        string? requiredComplianceStandard = null,
        JsonSerializerOptions? jsonSerializerOptions = null,
        int? bufferSize = null)
    {
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions
        {
            Converters = { new ElementSerializer() },
        };

        var handlers = new Dictionary<string, PropertyHandler>
        {
            { ContextProperty, new PropertyHandler<string>(ParameterType.Array) },
            { GraphProperty, new PropertyHandler<JsonNode>(ParameterType.Array) },
        };

        if (!string.IsNullOrEmpty(requiredComplianceStandard))
        {
            if (!Enum.TryParse<ComplianceStandard>(requiredComplianceStandard, true, out var complianceStandardAsEnum))
            {
                throw new ParserException($"{requiredComplianceStandard} compliance standard is not supported.");
            }
            else
            {
                switch (complianceStandardAsEnum)
                {
                    case ComplianceStandard.NTIA:
                        this.EntitiesToEnforceComplianceStandardsFor = this.entitiesWithDifferentNTIARequirements;
                        this.RequiredComplianceStandard = complianceStandardAsEnum;
                        break;
                    default:
                        throw new ParserException($"{requiredComplianceStandard} compliance standard is not supported.");
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
        ParserStateResult? result;
        do
        {
            result = this.parser.Next();
            if (result is not null)
            {
                this.observedFieldNames.Add(result.FieldName);
                if (result.Result is not null)
                {
                    switch (result.FieldName)
                    {
                        case ContextProperty:
                            result = new ContextsResult(result);
                            break;
                        case GraphProperty:
                            result = new ElementsResult(result);
                            break;
                        default:
                            throw new InvalidDataException($"Explicit field {result.FieldName} is unhandled.");
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

        return this.Metadata;
    }

    public ManifestInfo[] RegisterManifest() => new ManifestInfo[] { this.spdxManifestInfo };
}
