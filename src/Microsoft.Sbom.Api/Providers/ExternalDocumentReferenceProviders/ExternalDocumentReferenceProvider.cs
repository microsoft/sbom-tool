// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Utils;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Common.Config;
using Serilog;
using System;

namespace Microsoft.Sbom.Api.Providers.ExternalDocumentReferenceProviders
{
    /// <summary>
    /// Provider for external document reference. supported only when 
    /// ExternalDocumentReferenceListFile is provided in the generation arguments.
    /// </summary>
    public class ExternalDocumentReferenceProvider : EntityToJsonProviderBase<string>
    {
        public FileListEnumerator ListWalker { get; }

        public ISBOMReaderForExternalDocumentReference SPDXSBOMReaderForExternalDocumentReference { get; }

        public ExternalDocumentReferenceWriter ExternalDocumentReferenceWriter { get; }

        public ExternalReferenceDeduplicator ExternalReferenceDeduplicator { get; }

        public ExternalDocumentReferenceProvider(IConfiguration configuration, ChannelUtils channelUtils, ILogger logger, FileListEnumerator listWalker, ISBOMReaderForExternalDocumentReference spdxSbomReaderForExternalDocumentReference, ExternalDocumentReferenceWriter externalDocumentReferenceWriter, ExternalReferenceDeduplicator externalReferenceDeduplicator)
            : base(configuration, channelUtils, logger)
        {
            ListWalker = listWalker ?? throw new ArgumentNullException(nameof(listWalker));
            SPDXSBOMReaderForExternalDocumentReference = spdxSbomReaderForExternalDocumentReference ?? throw new ArgumentNullException(nameof(spdxSbomReaderForExternalDocumentReference));
            ExternalDocumentReferenceWriter = externalDocumentReferenceWriter ?? throw new ArgumentNullException(nameof(externalDocumentReferenceWriter));
            ExternalReferenceDeduplicator = externalReferenceDeduplicator ?? throw new ArgumentNullException(nameof(externalReferenceDeduplicator));
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
            var (results, parseErrors) = SPDXSBOMReaderForExternalDocumentReference.ParseSBOMFile(sourceChannel);
            errors.Add(parseErrors);
            results = ExternalReferenceDeduplicator.Deduplicate(results);
            var (jsonDoc, jsonErrors) = ExternalDocumentReferenceWriter.Write(results, requiredConfigs);
            errors.Add(jsonErrors);

            return (jsonDoc, ChannelUtils.Merge(errors.ToArray()));
        }

        protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
        {
            return ListWalker.GetFilesFromList(Configuration.ExternalDocumentReferenceListFile.Value);
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
        {
            return (null, null);
        }
    }
}
