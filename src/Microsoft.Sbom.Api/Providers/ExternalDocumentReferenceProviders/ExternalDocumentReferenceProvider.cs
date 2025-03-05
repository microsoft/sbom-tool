// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Providers.ExternalDocumentReferenceProviders;

/// <summary>
/// Provider for external document reference. supported only when
/// ExternalDocumentReferenceListFile is provided in the generation arguments.
/// </summary>
public class ExternalDocumentReferenceProvider : EntityToJsonProviderBase<string>
{
    private readonly FileListEnumerator listWalker;

    private readonly ISbomReaderForExternalDocumentReference spdxSbomReaderForExternalDocumentReference;

    private readonly ExternalDocumentReferenceWriter externalDocumentReferenceWriter;

    private readonly ExternalReferenceDeduplicator externalReferenceDeduplicator;

    public ExternalDocumentReferenceProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger logger,
        FileListEnumerator listWalker,
        ISbomReaderForExternalDocumentReference spdxSbomReaderForExternalDocumentReference,
        ExternalDocumentReferenceWriter externalDocumentReferenceWriter,
        ExternalReferenceDeduplicator externalReferenceDeduplicator)
        : base(configuration, channelUtils, logger)
    {
        this.listWalker = listWalker ?? throw new ArgumentNullException(nameof(listWalker));
        this.spdxSbomReaderForExternalDocumentReference = spdxSbomReaderForExternalDocumentReference ?? throw new ArgumentNullException(nameof(spdxSbomReaderForExternalDocumentReference));
        this.externalDocumentReferenceWriter = externalDocumentReferenceWriter ?? throw new ArgumentNullException(nameof(externalDocumentReferenceWriter));
        this.externalReferenceDeduplicator = externalReferenceDeduplicator ?? throw new ArgumentNullException(nameof(externalReferenceDeduplicator));
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.ExternalDocumentReference && !string.IsNullOrWhiteSpace(Configuration.ExternalDocumentReferenceListFile?.Value))
        {
            Log.Debug($"Using the {nameof(ExternalDocumentReferenceProvider)} provider for the external documents workflow.");
            return true;
        }

        return false;
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) ConvertToJson(ChannelReader<string> sourceChannel, IList<ISbomConfig> requiredConfigs)
    {
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();
        var (results, parseErrors) = spdxSbomReaderForExternalDocumentReference.ParseSbomFile(sourceChannel);
        errors.Add(parseErrors);
        results = externalReferenceDeduplicator.Deduplicate(results);
        var (jsonDoc, jsonErrors) = externalDocumentReferenceWriter.Write(results, requiredConfigs);
        errors.Add(jsonErrors);

        return (jsonDoc, ChannelUtils.Merge(errors.ToArray()));
    }

    protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        return listWalker.GetFilesFromList(Configuration.ExternalDocumentReferenceListFile.Value);
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
    {
        return (null, null);
    }
}
