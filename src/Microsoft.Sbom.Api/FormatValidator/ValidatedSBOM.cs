// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.FormatValidator;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;

public class ValidatedSBOM: IValidatedSBOM
{
    private readonly Stream sbomStream;
    private readonly int requiredSpdxMajorVersion = 2;
    private readonly RuntimeJsonPropertyValidator propertyValidator = new RuntimeJsonPropertyValidator(ignoredTypes: [typeof(IEnumerable<SPDXFile>)],
                                                                                                       requiredTypes: [typeof(IEnumerable<SPDXPackage>), typeof(IEnumerable<SPDXRelationship>)]);

    private readonly JsonSerializerOptions serializerOptions;
    private bool isInitialized = false;
    private FormatEnforcedSPDX2 sbom;

    private FormatValidationResults ValidationDetails { get; set; } = new FormatValidationResults();

    public ValidatedSBOM(Stream sbomStream)
    {
        this.sbomStream = sbomStream;
        serializerOptions = ConfigureSerializer();
    }

    public async Task<FormatValidationResults> GetValidationResults()
    {
        await Initialize();
        return ValidationDetails;
    }

    public async Task<FormatEnforcedSPDX2> GetRawSPDXDocument()
    {
        await Initialize();

        if (ValidationDetails.Status != FormatValidationStatus.Valid)
        {
            return null;
        }

        return sbom;
    }

    private async Task Initialize()
    {
        if (isInitialized)
        {
            return;
        }

        isInitialized = true;
        sbom = await Deserialize();
        ValidationDetails = Validate();
    }

    private async Task<FormatEnforcedSPDX2> Deserialize()
    {
        if (sbomStream is null)
        {
            ValidationDetails.AggregateValidationStatus(FormatValidationStatus.NotValid);
            ValidationDetails.Errors.Add("SBOM stream is null. Error reading file.");
            return null;
        }

        FormatEnforcedSPDX2 sbom = null;
        try
        {
            sbom = await JsonSerializer.DeserializeAsync<FormatEnforcedSPDX2>(sbomStream, serializerOptions);
        }
        catch (Exception e)
        {
            ValidationDetails.AggregateValidationStatus(FormatValidationStatus.NotValid);
            ValidationDetails.Errors.Add($"Error deserializing SBOM: {e.Message}");
        }

        return sbom;
    }

    private JsonSerializerOptions ConfigureSerializer()
    {
        var options = new JsonSerializerOptions()
        {
            TypeInfoResolver = new DefaultJsonTypeInfoResolver
            {
                Modifiers = { propertyValidator.UpdateTypeIgnoreOrRequire }
            }
        };

        return options;
    }

    private FormatValidationResults Validate()
    {
        if (sbom is null)
        {
            // Early return so we don't misleadingly report a version error when we actually
            // failed to deserialize.
            ValidationDetails.AggregateValidationStatus(FormatValidationStatus.NotValid);
            return ValidationDetails;
        }

        if (SPDXVersionParser.VersionMatchesRequiredVersion(sbom?.Version, requiredSpdxMajorVersion))
        {
            ValidationDetails.AggregateValidationStatus(FormatValidationStatus.Valid);
            return ValidationDetails;
        }

        ValidationDetails.AggregateValidationStatus(FormatValidationStatus.NotValid);
        ValidationDetails.Errors.Add($"SBOM version {sbom?.Version} is not recognized as SPDX major version 2.");
        return ValidationDetails;
    }

    public async Task<List<string>> MultilineSummary()
    {
        await Initialize();
        var description = new List<string>();

        if (ValidationDetails.Status != FormatValidationStatus.Valid)
        {
            description.Add("SBOM format validation failed. Please see the following errors:");
            description.Add("------------------------------");
            foreach (var error in ValidationDetails.Errors)
            {
                description.Add(error);
            }

            description.Add("------------------------------");
        }
        else
        {
            description.Add("SBOM format validation passed.");
            description.Add("------------------------------");
            description.Add($"SPDX Version: {sbom.Version}");
            description.Add($"Name: {sbom.Name}");
            description.Add($"Created: {sbom.CreationInfo?.Created}");

            foreach (var creator in sbom.CreationInfo?.Creators)
            {
                description.Add($"Creator: {creator}");
            }

            description.Add($"Contains {sbom.Files?.ToList().Count ?? 0} Files");
            description.Add($"Contains {sbom.Packages?.ToList().Count ?? 0} Packages");
            description.Add($"Contains {sbom.Relationships?.ToList().Count ?? 0} Relationships");
            description.Add($"Contains {sbom.ExternalDocumentReferences?.ToList().Count ?? 0} External Document References");
            description.Add($"Contains {sbom.Snippets?.ToList().Count ?? 0} Snippets");
            description.Add("------------------------------");
        }

        return description;
    }
}
