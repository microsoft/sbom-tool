// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

/// <summary>
/// Serialization methods for SPDX 3.0.
/// </summary>
internal class Spdx30SerializationStrategy : IJsonSerializationStrategy
{
    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns false since we do not want to write a separate files array in SPDX 3.0.
    /// A separate files array is only supported for SPDX 2.2.</returns>
    public bool AddToFilesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
        return false;
    }

    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns false since we do not want to write a separate packages array in SPDX 3.0.
    /// A separate packages array is only supported for SPDX 2.2.</returns>
    public bool AddToPackagesSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
        return false;
    }

    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns true since relationships are generated regardless of the config.</returns>
    public bool AddToRelationshipsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        return true;
    }

    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns false since we do not want to write a separate external document references array in SPDX 3.0.
    /// A separate external document references array is only supported for SPDX 2.2.</returns>
    public bool AddToExternalDocRefsSupportingConfig(IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs.Add(config);
        return false;
    }

    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config)
    {
        // Not supported for SPDX 3.0 and above, only supported for SPDX 2.2.
        // For SPDX 3.0 and above, the metadata is added as part of the SpdxDocument and CreationInfo elements.
    }

    public void StartGraphArray(ISbomConfig sbomConfig)
    {
        if (sbomConfig.ManifestInfo.Name == Constants.SPDX30ManifestInfo.Name &&
                sbomConfig.ManifestInfo.Version == Constants.SPDX30ManifestInfo.Version)
        {
            WriteContext(sbomConfig);
            sbomConfig.JsonSerializer.StartJsonArray(Constants.SPDXGraphHeaderName);
        }
    }

    public void EndGraphArray(ISbomConfig sbomConfig)
    {
        if (sbomConfig.ManifestInfo.Name == Constants.SPDX30ManifestInfo.Name &&
                sbomConfig.ManifestInfo.Version == Constants.SPDX30ManifestInfo.Version)
        {
            sbomConfig.JsonSerializer.EndJsonArray();
        }
    }

    /// <summary>
    /// Writes the JSON objects in >=SPDX 3.0 format.
    /// </summary>
    /// <param name="generationResult"></param>
    /// <param name="config"></param>
    /// <param name="elementsSpdxIdList">Only used for SPDX 3.0 and above for deduplication. SPDX 2.2 handles deduplication differently.</param>
    public void WriteJsonObjectsToManifest(GenerationResult generationResult, ISbomConfig config, HashSet<string> elementsSpdxIdList)
    {
        var serializer = config.JsonSerializer;

        if (generationResult.SerializerToJsonDocuments.TryGetValue(serializer, out var jsonDocuments))
        {
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
