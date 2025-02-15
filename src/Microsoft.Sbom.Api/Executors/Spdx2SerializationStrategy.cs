// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Serialization methods for SPDX 2.2.
/// </summary>
public class Spdx2SerializationStrategy : IJsonSerializationStrategy
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

    public void AddHeadersToSbom(ISbomConfigProvider sbomConfigs)
    {
        sbomConfigs.ApplyToEachConfig(config =>
            config.JsonSerializer.WriteJsonString(
                config.MetadataBuilder.GetHeaderJsonString(sbomConfigs)));
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

        await WriteFiles(fileArrayGenerator);

        await WritePackages(packageArrayGenerator);

        await WriteExternalDocRefs(externalDocumentReferenceGenerator);

        await WriteRelationships(relationshipsArrayGenerator);

        return errors;
    }

    /// <summary>
    /// Write to Files section
    /// </summary>
    /// <param name="fileArrayGenerator"></param>
    /// <returns></returns>
    private async Task WriteFiles(IJsonArrayGenerator<FileArrayGenerator> fileArrayGenerator)
    {
        var filesGenerateResult = await fileArrayGenerator.GenerateAsync();
        filesGenerateResult.Errors.AddRange(filesGenerateResult.Errors);
        WriteJsonObjectsFromGenerationResult(filesGenerateResult, fileArrayGenerator.SbomConfig);
        EndJsonArrayForElementsSupportingConfigs(filesGenerateResult);
    }

    /// <summary>
    /// Write to Packages section
    /// </summary>
    /// <param name="packageArrayGenerator"></param>
    /// <returns></returns>
    private async Task WritePackages(IJsonArrayGenerator<PackageArrayGenerator> packageArrayGenerator)
    {
        var packagesGenerateResult = await packageArrayGenerator.GenerateAsync();
        packagesGenerateResult.Errors.AddRange(packagesGenerateResult.Errors);
        WriteJsonObjectsFromGenerationResult(packagesGenerateResult, packageArrayGenerator.SbomConfig);
        EndJsonArrayForElementsSupportingConfigs(packagesGenerateResult);
    }

    /// <summary>
    /// Write to External Document Reference section
    /// </summary>
    /// <param name="externalDocumentReferenceGenerator"></param>
    /// <returns></returns>
    private async Task WriteExternalDocRefs(IJsonArrayGenerator<ExternalDocumentReferenceGenerator> externalDocumentReferenceGenerator)
    {
        var externalDocumentReferenceGenerateResult = await externalDocumentReferenceGenerator.GenerateAsync();
        externalDocumentReferenceGenerateResult.Errors.AddRange(externalDocumentReferenceGenerateResult.Errors);
        WriteJsonObjectsFromGenerationResult(externalDocumentReferenceGenerateResult, externalDocumentReferenceGenerator.SbomConfig);
        EndJsonArrayForElementsSupportingConfigs(externalDocumentReferenceGenerateResult);
    }

    /// <summary>
    /// Write to Relationships section
    /// </summary>
    /// <param name="relationshipsArrayGenerator"></param>
    /// <returns></returns>
    private async Task WriteRelationships(IJsonArrayGenerator<RelationshipsArrayGenerator> relationshipsArrayGenerator)
    {
        var relationshipGenerateResult = await relationshipsArrayGenerator.GenerateAsync();
        relationshipGenerateResult.Errors.AddRange(relationshipGenerateResult.Errors);
        WriteJsonObjectsFromGenerationResult(relationshipGenerateResult, relationshipsArrayGenerator.SbomConfig);
        EndJsonArrayForSbomConfig(relationshipsArrayGenerator.SbomConfig);
    }

    private void WriteJsonObjectsFromGenerationResult(GenerationResult generationResult, ISbomConfig sbomConfig)
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
        }
    }

    private void EndJsonArrayForElementsSupportingConfigs(GenerationResult generationResult)
    {
        foreach (var serializer in generationResult.SerializerToJsonDocuments.Keys)
        {
            serializer.EndJsonArray();
        }
    }

    private void EndJsonArrayForSbomConfig(ISbomConfig sbomConfig)
    {
        sbomConfig.JsonSerializer.EndJsonArray();
    }
}
