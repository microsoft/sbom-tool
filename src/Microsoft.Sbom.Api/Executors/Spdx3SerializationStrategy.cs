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
public class Spdx3SerializationStrategy : IJsonSerializationStrategy
{
    public void AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
    }

    public void AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
    }

    public bool AddToRelationshipsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        return true;
    }

    public void AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
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
        var generateResult = await fileArrayGenerator.GenerateAsync();
        WriteElementsToSbom(generateResult, elementsSpdxIdList);

        // Packages section
        var packagesGenerateResult = await packageArrayGenerator.GenerateAsync();
        generateResult.Errors.AddRange(packagesGenerateResult.Errors);
        WriteElementsToSbom(packagesGenerateResult, elementsSpdxIdList);

        // External Document Reference section
        var externalDocumentReferenceGenerateResult = await externalDocumentReferenceGenerator.GenerateAsync();
        generateResult.Errors.AddRange(externalDocumentReferenceGenerateResult.Errors);
        WriteElementsToSbom(externalDocumentReferenceGenerateResult, elementsSpdxIdList);

        // Relationships section
        var relationshipGenerateResult = await relationshipsArrayGenerator.GenerateAsync();
        generateResult.Errors.AddRange(relationshipGenerateResult.Errors);
        WriteElementsToSbom(relationshipGenerateResult, elementsSpdxIdList);

        sbomConfig.JsonSerializer.EndJsonArray();

        return generateResult.Errors;
    }

    private void WriteElementsToSbom(GenerationResult generateResult, HashSet<string> elementsSpdxIdList)
    {
        // Write the JSON objects to the SBOM
        foreach (var serializer in generateResult.SerializerToJsonDocuments.Keys)
        {
            var jsonDocuments = generateResult.SerializerToJsonDocuments[serializer];
            foreach (var jsonDocument in jsonDocuments)
            {
                if (jsonDocument.RootElement.ValueKind == JsonValueKind.Object)
                {
                    WriteElement(serializer, jsonDocument.RootElement, elementsSpdxIdList);
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

    private void WriteElement(IManifestToolJsonSerializer serializer, JsonElement element, HashSet<string> elementsSpdxIdList)
    {
        if (element.TryGetProperty("spdxId", out var spdxIdField))
        {
            var spdxId = spdxIdField.GetString();

            if (elementsSpdxIdList.TryGetValue(spdxId, out _))
            {
                return;
            }
            else
            {
                serializer.Write(element);
                elementsSpdxIdList.Add(spdxId);
            }
        }
    }
}
