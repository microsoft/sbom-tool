// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using System;
using Serilog;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Providers.ExternalDocumentReferenceProviders;

/// <summary>
/// Provider for external document reference which leverage component detection tool
/// to discover SBOM files.
/// </summary>
public class CGExternalDocumentReferenceProvider : EntityToJsonProviderBase<ScannedComponent>
{
    private readonly ComponentToExternalReferenceInfoConverter componentToExternalReferenceInfoConverter;

    private readonly ExternalDocumentReferenceWriter externalDocumentReferenceWriter;

    private readonly SBOMComponentsWalker sbomComponentsWalker;

    private readonly ExternalReferenceDeduplicator externalReferenceDeduplicator;

    public CGExternalDocumentReferenceProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger logger,
        ComponentToExternalReferenceInfoConverter componentToExternalReferenceInfoConverter,
        ExternalDocumentReferenceWriter externalDocumentReferenceWriter,
        SBOMComponentsWalker sbomComponentsWalker,
        ExternalReferenceDeduplicator externalReferenceDeduplicator)
        : base(configuration, channelUtils, logger)
    {
        this.componentToExternalReferenceInfoConverter = componentToExternalReferenceInfoConverter ?? throw new ArgumentNullException(nameof(componentToExternalReferenceInfoConverter));
        this.externalDocumentReferenceWriter = externalDocumentReferenceWriter ?? throw new ArgumentNullException(nameof(externalDocumentReferenceWriter));
        this.sbomComponentsWalker = sbomComponentsWalker ?? throw new ArgumentNullException(nameof(sbomComponentsWalker));
        this.externalReferenceDeduplicator = externalReferenceDeduplicator ?? throw new ArgumentNullException(nameof(externalReferenceDeduplicator));
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.ExternalDocumentReference)
        {
            Log.Debug($"Using the {nameof(CGExternalDocumentReferenceProvider)} provider for the external documents workflow.");
            return true;
        }

        return false;
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) ConvertToJson(ChannelReader<ScannedComponent> sourceChannel, IList<ISbomConfig> requiredConfigs)
    {
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

        var (output, convertErrors) = componentToExternalReferenceInfoConverter.Convert(sourceChannel);
        errors.Add(convertErrors);
        output = externalReferenceDeduplicator.Deduplicate(output);

        var (jsonDoc, jsonErrors) = externalDocumentReferenceWriter.Write(output, requiredConfigs);
        errors.Add(jsonErrors);

        return (jsonDoc, ChannelUtils.Merge(errors.ToArray()));
    }

    protected override (ChannelReader<ScannedComponent> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        var (output, cdErrors) = sbomComponentsWalker.GetComponents(Configuration.BuildComponentPath?.Value);

        if (cdErrors.TryRead(out ComponentDetectorException e))
        {
            throw e;
        }

        var errors = Channel.CreateUnbounded<FileValidationResult>();
        errors.Writer.Complete();
        return (output, errors);
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
    {
        return (null, null);
    }
}