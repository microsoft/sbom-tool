// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
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
    /// <returns>Always returns false since we do not want to write a separate files array in SPDX 3.0.</returns>
    public bool AddToFilesSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs = elementsSupportingConfigs.Append(config);
        return false;
    }

    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns false since we do not want to write a separate packages array in SPDX 3.0.</returns>
    public bool AddToPackagesSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs = elementsSupportingConfigs.Append(config);
        return false;
    }

    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns true since relationships are generated regardless of the config.</returns>
    public bool AddToRelationshipsSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        return true;
    }

    /// <summary>
    /// inheritdoc
    /// </summary>
    /// <param name="elementsSupportingConfigs"></param>
    /// <param name="config"></param>
    /// <returns>Always returns false since we do not want to write a separate external document references array in SPDX 3.0.</returns>
    public bool AddToExternalDocRefsSupportingConfig(IEnumerable<ISbomConfig> elementsSupportingConfigs, ISbomConfig config)
    {
        elementsSupportingConfigs = elementsSupportingConfigs.Append(config);
        return false;
    }

    public void AddMetadataToSbom(ISbomConfigProvider sbomConfigs, ISbomConfig config)
    {
        // Not supported for SPDX 3.0.
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
    /// Writes the JSON objects in SPDX 3.0 format.
    /// </summary>
    /// <param name="generationResult"></param>
    /// <param name="config"></param>
    /// <param name="elementsSpdxIdList">Hashes for deduplication in SPDX 3.0.</param>
    public void WriteJsonObjectsToManifest(GenerationResult generationResult, ISbomConfig config, ISet<string> elementsSpdxIdList)
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

    private void WriteElement(IManifestToolJsonSerializer serializer, JsonElement element, ISet<string> elementsSpdxIdList)
    {
        if (element.TryGetProperty("spdxId", out var spdxIdField))
        {
            var spdxId = spdxIdField.GetString();

            if (elementsSpdxIdList.Contains(spdxId))
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
