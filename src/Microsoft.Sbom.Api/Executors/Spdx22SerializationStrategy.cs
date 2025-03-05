// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Serialization methods for SPDX 2.2.
/// </summary>
internal class Spdx22SerializationStrategy : IJsonSerializationStrategy
{
    public void AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetFilesArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs.Add(config);
        }
    }

    public void AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetPackageArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs.Add(config);
        }
    }

    public bool AddToRelationshipsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetRelationshipsHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            return true;
        }

        return false;
        }

    public void AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetExternalRefArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs.Add(config);
        }
    }

    public void AddHeadersToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config)
    {
        config.JsonSerializer?.WriteJsonString(config.MetadataBuilder.GetHeaderJsonString(sbomConfigs));
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

        var errors = new List<FileValidationResult>();

        await WriteFiles(fileArrayGenerator, errors);

        await WritePackages(packageArrayGenerator, errors);

        await WriteExternalDocRefs(externalDocumentReferenceGenerator, errors);

        await WriteRelationships(relationshipsArrayGenerator, errors);

        return errors;
    }

    /// <summary>
    /// Write to Files section
    /// </summary>
    /// <param name="fileArrayGenerator"></param>
    /// <returns></returns>
    private async Task WriteFiles(IJsonArrayGenerator<FileArrayGenerator> fileArrayGenerator, List<FileValidationResult> errors)
    {
        var filesGenerationResult = await fileArrayGenerator.GenerateAsync();
        errors.AddRange(filesGenerationResult.Errors);
        WriteJsonObjectsFromGenerationResult(filesGenerationResult, fileArrayGenerator.SbomConfig);
    }

    /// <summary>
    /// Write to Packages section
    /// </summary>
    /// <param name="packageArrayGenerator"></param>
    /// <returns></returns>
    private async Task WritePackages(IJsonArrayGenerator<PackageArrayGenerator> packageArrayGenerator, List<FileValidationResult> errors)
    {
        var packagesGenerationResult = await packageArrayGenerator.GenerateAsync();
        errors.AddRange(packagesGenerationResult.Errors);
        WriteJsonObjectsFromGenerationResult(packagesGenerationResult, packageArrayGenerator.SbomConfig);
    }

    /// <summary>
    /// Write to External Document Reference section
    /// </summary>
    /// <param name="externalDocumentReferenceGenerator"></param>
    /// <returns></returns>
    private async Task WriteExternalDocRefs(IJsonArrayGenerator<ExternalDocumentReferenceGenerator> externalDocumentReferenceGenerator, List<FileValidationResult> errors)
    {
        var externalDocumentReferenceGenerationResult = await externalDocumentReferenceGenerator.GenerateAsync();
        errors.AddRange(externalDocumentReferenceGenerationResult.Errors);
        WriteJsonObjectsFromGenerationResult(externalDocumentReferenceGenerationResult, externalDocumentReferenceGenerator.SbomConfig, externalDocumentReferenceGenerationResult.SourcesProviders);
    }

    /// <summary>
    /// Write to Relationships section
    /// </summary>
    /// <param name="relationshipsArrayGenerator"></param>
    /// <returns></returns>
    private async Task WriteRelationships(IJsonArrayGenerator<RelationshipsArrayGenerator> relationshipsArrayGenerator, List<FileValidationResult> errors)
    {
        var relationshipGenerationResult = await relationshipsArrayGenerator.GenerateAsync();
        errors.AddRange(relationshipGenerationResult.Errors);
        WriteJsonObjectsFromGenerationResult(relationshipGenerationResult, relationshipsArrayGenerator.SbomConfig);
   }

    private void WriteJsonObjectsFromGenerationResult(GenerationResult generationResult, ISbomConfig sbomConfig, IEnumerable<ISourcesProvider> sourcesProviders = null)
    {
        foreach (var serializer in generationResult.SerializerToJsonDocuments.Keys)
        {
            var jsonDocuments = generationResult.SerializerToJsonDocuments[serializer];
            if (jsonDocuments.Count > 0)
            {
                foreach (var jsonDocument in jsonDocuments)
                {
                    serializer.Write(jsonDocument);
                }
            }

            serializer.EndJsonArray();
        }

        if (sourcesProviders is not null)
        {
            sbomConfig.JsonSerializer.EndJsonArray();
        }
    }
}
