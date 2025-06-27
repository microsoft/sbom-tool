// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text.Json;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Output;

/// <summary>
/// Provides metadata that can be added to an SBOM.
/// as a header.
/// </summary>
public class MetadataBuilder : IMetadataBuilder
{
    private readonly IManifestGenerator manifestGenerator;
    private readonly ILogger logger;
    private readonly ManifestInfo manifestInfo;
    private readonly IRecorder recorder;

    public MetadataBuilder(
        ILogger logger,
        ManifestGeneratorProvider manifestGeneratorProvider,
        ManifestInfo manifestInfo,
        IRecorder recorder)
    {
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        this.manifestInfo = manifestInfo ?? throw new ArgumentNullException(nameof(manifestInfo));
        manifestGenerator = manifestGeneratorProvider
            .Get(manifestInfo);
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    /// <summary>
    /// Gets the json string value of the header dictionary.
    /// </summary>
    /// <returns></returns>
    public string GetHeaderJsonString(IInternalMetadataProvider internalMetadataProvider)
    {
        // SPDX 3.0 and above handles writing the info in metadata dictionary differently.
        // Note: manifestGenerator.Version is a string that is formatted as <manifestInfoName>-<manifestInfoVersion>.
        if (manifestGenerator.Version.Contains(Constants.SPDX30ManifestInfo.Name)
            && manifestGenerator.Version.Contains(Constants.SPDX30ManifestInfo.Version))
        {
            logger.Debug($"The SBOM format '{Constants.SPDX30ManifestInfo}' does not support writing a metadata dictionary.");
        }

        using (recorder.TraceEvent(string.Format(Events.MetadataBuilder, manifestInfo)))
        {
            logger.Debug("Building the header object.");
            var headerDictionary = manifestGenerator.GetMetadataDictionary(internalMetadataProvider);
            return JsonSerializer.Serialize(headerDictionary);
        }
    }

    public bool TryGetFilesArrayHeaderName(out string headerName)
    {
        try
        {
            headerName = manifestGenerator.FilesArrayHeaderName;
            return true;
        }
        catch (NotSupportedException)
        {
            headerName = null;
            logger.Warning("Files array not supported on this SBOM format.");
            return false;
        }
    }

    public bool TryGetPackageArrayHeaderName(out string headerName)
    {
        try
        {
            headerName = manifestGenerator.PackagesArrayHeaderName;
            return true;
        }
        catch (NotSupportedException)
        {
            headerName = null;
            logger.Warning("Packages array not supported on this SBOM format.");
            return false;
        }
    }

    public bool TryGetExternalRefArrayHeaderName(out string headerName)
    {
        try
        {
            headerName = manifestGenerator.ExternalDocumentRefArrayHeaderName;
            return true;
        }
        catch (NotSupportedException)
        {
            headerName = null;
            logger.Warning("External Document Reference array not supported on this SBOM format.");
            return false;
        }
    }

    public bool TryGetRootPackageJson(IInternalMetadataProvider internalMetadataProvider, out GenerationResult generationResult)
    {
        try
        {
            generationResult = manifestGenerator.GenerateRootPackage(internalMetadataProvider);

            if (generationResult == null)
            {
                return false;
            }

            return true;
        }
        catch (NotSupportedException)
        {
            generationResult = null;
            logger.Warning("Root package serialization not supported on this SBOM format.");
            return false;
        }
    }

    public bool TryGetCreationInfoJson(IInternalMetadataProvider internalMetadataProvider, out GenerationResult generationResult)
    {
        try
        {
            generationResult = manifestGenerator.GenerateJsonDocument(internalMetadataProvider);

            if (generationResult == null)
            {
                return false;
            }

            return true;
        }
        catch (NotSupportedException)
        {
            generationResult = null;
            logger.Warning("Root package serialization is not supported on this SBOM format.");
            return false;
        }
    }

    public bool TryGetRelationshipsHeaderName(out string headerName)
    {
        try
        {
            headerName = manifestGenerator.RelationshipsArrayHeaderName;
            return headerName != null;
        }
        catch (NotSupportedException)
        {
            headerName = null;
            logger.Warning("Relationships array are not supported on this SBOM format.");
            return false;
        }
    }
}
