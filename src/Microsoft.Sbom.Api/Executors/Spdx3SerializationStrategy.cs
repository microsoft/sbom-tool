// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
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
    public void AddToFilesSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
    }

    public void AddToPackagesSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
    }

    public bool AddToRelationshipsSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        return true;
    }

    public void AddToExternalDocRefsSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
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

        // Files section
        var generateResult = await fileArrayGenerator.GenerateAsync();
        WriteElementsToSbom(generateResult);

        // Packages section
        var packagesGenerateResult = await packageArrayGenerator.GenerateAsync();
        generateResult.Errors.AddRange(packagesGenerateResult.Errors);
        WriteElementsToSbom(packagesGenerateResult);

        // External Document Reference section
        var externalDocumentReferenceGenerateResult = await externalDocumentReferenceGenerator.GenerateAsync();
        generateResult.Errors.AddRange(externalDocumentReferenceGenerateResult.Errors);
        WriteElementsToSbom(externalDocumentReferenceGenerateResult);

        // Relationships section
        var relationshipGenerateResult = await relationshipsArrayGenerator.GenerateAsync();
        generateResult.Errors.AddRange(relationshipGenerateResult.Errors);
        WriteElementsToSbom(relationshipGenerateResult);

        return generateResult.Errors;
    }

    private void WriteElementsToSbom(GenerateResult generateResult)
    {
        // Write the JSON objects to the SBOM
        foreach (var serializer in generateResult.SerializerToJsonDocuments.Keys)
        {
            // Write context
            serializer.StartJsonArray("@context");
            var document = JsonDocument.Parse(Constants.Spdx3Context);
            serializer.Write(document);
            serializer.EndJsonArray();

            // Deduplication of elements by checking SPDX ID
            var elementsSpdxIdList = new HashSet<string>();

            serializer.StartJsonArray("@graph");

            var jsonDocuments = generateResult.SerializerToJsonDocuments[serializer];
            foreach (var jsonDocument in jsonDocuments)
            {
                foreach (var element in jsonDocument.RootElement.EnumerateArray())
                {
                    if (element.TryGetProperty("spdxId", out var spdxIdField))
                    {
                        var spdxId = spdxIdField.GetString();

                        if (!elementsSpdxIdList.TryGetValue(spdxId, out _))
                        {
                            serializer.Write(element);
                            elementsSpdxIdList.Add(spdxId);
                        }
                        else
                        {
                            Console.WriteLine($"Duplicate element with SPDX ID {spdxId} found. Skipping.");
                        }
                    }
                }
            }

            serializer.EndJsonArray();
        }
    }
}
