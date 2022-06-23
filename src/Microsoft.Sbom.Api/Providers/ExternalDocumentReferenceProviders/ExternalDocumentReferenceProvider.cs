// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Api.Utils;
using Ninject;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;

namespace Microsoft.Sbom.Api.Providers.ExternalDocumentReferenceProviders
{
    /// <summary>
    /// Provider for external document reference. supported only when 
    /// ExternalDocumentReferenceListFile is provided in the generation arguments.
    /// </summary>
    public class ExternalDocumentReferenceProvider : EntityToJsonProviderBase<string>
    {
        [Inject]
        public FileListEnumerator ListWalker { get; set; }

        [Inject]
        public ISBOMReaderForExternalDocumentReference SPDXSBOMReaderForExternalDocumentReference { get; set; }

        [Inject]
        public ExternalDocumentReferenceWriter ExternalDocumentReferenceWriter { get; set; }

        [Inject]
        public ExternalReferenceDeduplicator ExternalReferenceDeduplicator { get; set; }

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
