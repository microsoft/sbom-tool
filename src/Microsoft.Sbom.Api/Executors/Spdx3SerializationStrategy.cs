// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions;
using SpdxConstants = Microsoft.Sbom.Constants.SpdxConstants;

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

    private void WriteElementsToSbom(GenerationResult generateResult)
    {
        // Write the JSON objects to the SBOM
        foreach (var serializer in generateResult.SerializerToJsonDocuments.Keys)
        {
            // Write context
            serializer.StartJsonArray(SpdxConstants.SPDXContextHeaderName);
            var document = JsonDocument.Parse(SpdxConstants.SPDX3ContextValue);
            serializer.Write(document);
            serializer.EndJsonArray();

            // Deduplication of elements by checking SPDX ID
            var elementsSpdxIdList = new HashSet<string>();

            serializer.StartJsonArray(SpdxConstants.SPDXGraphHeaderName);

            var jsonDocuments = generateResult.SerializerToJsonDocuments[serializer];
            foreach (var jsonDocument in jsonDocuments)
            {
                foreach (var element in jsonDocument.RootElement.EnumerateArray())
                {
                    if (element.TryGetProperty("spdxId", out var spdxIdField))
                    {
                        var spdxId = spdxIdField.GetString();

                        if (elementsSpdxIdList.TryGetValue(spdxId, out _))
                        {
                            Console.WriteLine($"Duplicate element with SPDX ID {spdxId} found. Skipping.");
                        }
                        else
                        {
                            serializer.Write(element);
                            elementsSpdxIdList.Add(spdxId);
                        }
                    }
                }
            }

            serializer.EndJsonArray();
        }
    }
}
