// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Serialization methods for SPDX 2.2.
/// </summary>
internal class Spdx22SerializationStrategy : IJsonSerializationStrategy
{
    public bool AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetFilesArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs.Add(config);
            return true;
        }

        return false;
    }

    public bool AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetPackageArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs.Add(config);
            return true;
        }

        return false;
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

    public bool AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        if (config.MetadataBuilder.TryGetExternalRefArrayHeaderName(out var headerName))
        {
            config.JsonSerializer.StartJsonArray(headerName);
            elementsSupportingConfigs.Add(config);
            return true;
        }

        return false;
    }

    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config)
    {
        config.JsonSerializer?.WriteJsonString(config.MetadataBuilder.GetHeaderJsonString(sbomConfigs));
    }

    public void StartGraphArray(IList<ManifestInfo> manifestInfosFromConfig, ISbomConfigProvider sbomConfigs)
    {
        // Not supported for SPDX 2.2, only supported for SPDX 3.0 and above.
    }

    public void EndGraphArray(IList<ManifestInfo> manifestInfosFromConfig, ISbomConfigProvider sbomConfigs)
    {
        // Not supported for SPDX 2.2, only supported for SPDX 3.0 and above.
    }

    public void WriteJsonObjectsToManifest(GenerationResult generationResult)
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

        foreach (var sbomConfig in generationResult.JsonArrayStartedForConfig)
        {
            if (sbomConfig.Value)
            {
                sbomConfig.Key.JsonSerializer.EndJsonArray();
            }
        }
    }
}
