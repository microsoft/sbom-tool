// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
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

        var generateResult = await fileArrayGenerator.GenerateAsync();

        // Packages section
        var packagesGenerateResult = await packageArrayGenerator.GenerateAsync();
        generateResult.Errors.AddRange(packagesGenerateResult.Errors);

        // External Document Reference section
        var externalDocumentReferenceGenerateResult = await externalDocumentReferenceGenerator.GenerateAsync();
        generateResult.Errors.AddRange(externalDocumentReferenceGenerateResult.Errors);

        // Relationships section
        var relationshipGenerateResult = await relationshipsArrayGenerator.GenerateAsync();
        generateResult.Errors.AddRange(relationshipGenerateResult.Errors);

        // Write the JSON objects to the SBOM
        // TODO: avoid this for loop
        // TODO: can add deduplication here
        foreach (var serializer in generateResult.SerializerToJsonDocuments.Keys)
        {
            serializer.StartJsonArray("@graph");

            var jsonDocuments = generateResult.SerializerToJsonDocuments[serializer];
            foreach (var jsonDocument in jsonDocuments)
            {
                foreach (var element in jsonDocument.RootElement.EnumerateArray())
                {
                    serializer.Write(element);
                }
            }

            serializer.EndJsonArray();
        }

        return generateResult.Errors;
    }
}
