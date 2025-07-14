// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog;

namespace Microsoft.Sbom.Api.Providers.FilesProviders;

/// <summary>
/// Provider for external document reference which leverage component detection tool
/// to discover SBOM files.
/// </summary>
public class CGScannedExternalDocumentReferenceFileProvider : PathBasedFileToJsonProviderBase
{
    public ComponentToExternalReferenceInfoConverter ComponentToExternalReferenceInfoConverter { get; }

    public ExternalReferenceInfoToPathConverter ExternalReferenceInfoToPathConverter { get; }

    public ExternalDocumentReferenceWriter ExternalDocumentReferenceWriter { get; }

    public SbomComponentsWalker SbomComponentsWalker { get; }

    public CGScannedExternalDocumentReferenceFileProvider(
        IConfiguration configuration,
        ChannelUtils channelUtils,
        ILogger log,
        FileHasher fileHasher,
        ManifestFolderFilterer fileFilterer,
        FileInfoWriter fileHashWriter,
        InternalSbomFileInfoDeduplicator internalSbomFileInfoDeduplicator,
        ComponentToExternalReferenceInfoConverter componentToExternalReferenceInfoConverter,
        ExternalReferenceInfoToPathConverter externalReferenceInfoToPathConverter,
        ExternalDocumentReferenceWriter externalDocumentReferenceWriter,
        SbomComponentsWalker sbomComponentsWalker)
        : base(configuration, channelUtils, log, fileHasher, fileFilterer, fileHashWriter, internalSbomFileInfoDeduplicator)
    {
        ComponentToExternalReferenceInfoConverter = componentToExternalReferenceInfoConverter ?? throw new ArgumentNullException(nameof(componentToExternalReferenceInfoConverter));
        ExternalReferenceInfoToPathConverter = externalReferenceInfoToPathConverter ?? throw new ArgumentNullException(nameof(externalReferenceInfoToPathConverter));
        ExternalDocumentReferenceWriter = externalDocumentReferenceWriter ?? throw new ArgumentNullException(nameof(externalDocumentReferenceWriter));
        SbomComponentsWalker = sbomComponentsWalker ?? throw new ArgumentNullException(nameof(sbomComponentsWalker));
    }

    public override bool IsSupported(ProviderType providerType)
    {
        if (providerType == ProviderType.Files && Configuration.ManifestToolAction != ManifestToolActions.Aggregate)
        {
            Log.Debug($"Using the {nameof(CGScannedExternalDocumentReferenceFileProvider)} provider for the files workflow.");
            return true;
        }

        return false;
    }

    protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
    {
        var (sbomOutput, cdErrors) = SbomComponentsWalker.GetComponents(Configuration.BuildComponentPath?.Value);
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

        if (cdErrors.TryRead(out var e))
        {
            throw e;
        }

        var (externalRefDocOutput, externalRefDocErrors) = ComponentToExternalReferenceInfoConverter.Convert(sbomOutput);
        errors.Add(externalRefDocErrors);

        var (pathOutput, pathErrors) = ExternalReferenceInfoToPathConverter.Convert(externalRefDocOutput);
        errors.Add(pathErrors);

        return (pathOutput, ChannelUtils.Merge(errors.ToArray()));
    }

    protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
    {
        return (null, null);
    }
}
