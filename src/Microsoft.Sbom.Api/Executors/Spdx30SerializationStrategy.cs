// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Serialization methods for SPDX 3.0.
/// </summary>
internal class Spdx30SerializationStrategy : IJsonSerializationStrategy
{
    public bool AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
        return true;
    }

    public bool AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
        return true;
    }

    public bool AddToRelationshipsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        return true;
    }

    public bool AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
        return true;
    }

    public async Task<List<FileValidationResult>> WriteJsonObjectsToSbomAsync(
        ISbomConfig sbomConfig,
        string spdxManifestVersion,
        IJsonArrayGenerator<FileArrayGenerator> fileArrayGenerator,
        IJsonArrayGenerator<PackageArrayGenerator> packageArrayGenerator,
        IJsonArrayGenerator<RelationshipsArrayGenerator> relationshipsArrayGenerator,
        IJsonArrayGenerator<ExternalDocumentReferenceGenerator> externalDocumentReferenceGenerator)
    {
        fileArrayGenerator.SbomConfig = sbomConfig;
        packageArrayGenerator.SbomConfig = sbomConfig;
        relationshipsArrayGenerator.SbomConfig = sbomConfig;
        externalDocumentReferenceGenerator.SbomConfig = sbomConfig;

        fileArrayGenerator.SpdxManifestVersion = spdxManifestVersion;
        packageArrayGenerator.SpdxManifestVersion = spdxManifestVersion;
        relationshipsArrayGenerator.SpdxManifestVersion = spdxManifestVersion;
        externalDocumentReferenceGenerator.SpdxManifestVersion = spdxManifestVersion;

        // Holds the SPDX IDs of all the elements that have been written to the SBOM. Used for deduplication.
        var elementsSpdxIdList = new HashSet<string>();

        WriteContext(sbomConfig);

        sbomConfig.JsonSerializer.StartJsonArray(Constants.SPDXGraphHeaderName);

        // Files section
        var generationResult = await fileArrayGenerator.GenerateAsync();
        WriteElementsToSbom(generationResult, elementsSpdxIdList);

        // Packages section
        var packagesGenerationResult = await packageArrayGenerator.GenerateAsync();
        generationResult.Errors.AddRange(packagesGenerationResult.Errors);
        WriteElementsToSbom(packagesGenerationResult, elementsSpdxIdList);

        // External Document Reference section
        var externalDocumentReferenceGenerationResult = await externalDocumentReferenceGenerator.GenerateAsync();
        generationResult.Errors.AddRange(externalDocumentReferenceGenerationResult.Errors);
        WriteElementsToSbom(externalDocumentReferenceGenerationResult, elementsSpdxIdList);

        // Relationships section
        var relationshipGenerationResult = await relationshipsArrayGenerator.GenerateAsync();
        generationResult.Errors.AddRange(relationshipGenerationResult.Errors);
        WriteElementsToSbom(relationshipGenerationResult, elementsSpdxIdList);

        sbomConfig.JsonSerializer.EndJsonArray();

        return generationResult.Errors;
    }

    private void WriteElementsToSbom(GenerationResult generationResult, HashSet<string> elementsSpdxIdList)
    {
        var count = 0;
        var duplicateElementCount = 0;
        // Write the JSON objects to the SBOM
        foreach (var serializer in generationResult.SerializerToJsonDocuments.Keys)
        {
            var jsonDocuments = generationResult.SerializerToJsonDocuments[serializer];
            foreach (var jsonDocument in jsonDocuments)
            {
                if (jsonDocument.RootElement.ValueKind == JsonValueKind.Object)
                {
                    var isDuplicate = WriteElement(serializer, jsonDocument.RootElement, elementsSpdxIdList);
                    if (isDuplicate)
                    {
                        duplicateElementCount++;
                    }
                    else
                    {
                        count++;
                    }
                }
                else
                {
                    foreach (var element in jsonDocument.RootElement.EnumerateArray())
                    {
                        WriteElement(serializer, element, elementsSpdxIdList);
                    }
                }
            }
        }
    }

    private void WriteContext(ISbomConfig sbomConfig)
    {
        sbomConfig.JsonSerializer.StartJsonArray(Constants.SPDXContextHeaderName);
        var document = JsonDocument.Parse(Constants.SPDX3ContextValue);
        sbomConfig.JsonSerializer.Write(document);
        sbomConfig.JsonSerializer.EndJsonArray();
    }

    private bool WriteElement(IManifestToolJsonSerializer serializer, JsonElement element, HashSet<string> elementsSpdxIdList)
    {
        var duplicateElement = false;
        if (element.TryGetProperty("spdxId", out var spdxIdField))
        {
            var spdxId = spdxIdField.GetString();

            if (elementsSpdxIdList.TryGetValue(spdxId, out _))
            {
                duplicateElement = true;
                return duplicateElement;
            }
            else
            {
                serializer.Write(element);
                elementsSpdxIdList.Add(spdxId);
            }
        }

        return duplicateElement;
    }
}
