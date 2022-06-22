﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
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
    /// Provider for external document reference which leverage component detection tool
    /// to discover SBOM files.
    /// </summary>
    public class CGExternalDocumentReferenceProvider : EntityToJsonProviderBase<ScannedComponent>
    {
        [Inject]
        public ComponentToExternalReferenceInfoConverter ComponentToExternalReferenceInfoConverter { get; set; }

        [Inject]
        public ExternalDocumentReferenceWriter ExternalDocumentReferenceWriter { get; set; }

        [Inject]
        public SBOMComponentsWalker SBOMComponentsWalker { get; set; }

        [Inject]
        public ExternalReferenceDeduplicator ExternalReferenceDeduplicator { get; set; }

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

            var (output, convertErrors) = ComponentToExternalReferenceInfoConverter.Convert(sourceChannel);
            errors.Add(convertErrors);
            output = ExternalReferenceDeduplicator.Deduplicate(output);

            var (jsonDoc, jsonErrors) = ExternalDocumentReferenceWriter.Write(output, requiredConfigs);
            errors.Add(jsonErrors);

            return (jsonDoc, ChannelUtils.Merge(errors.ToArray()));
        }

        protected override (ChannelReader<ScannedComponent> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
        {
            var (output, cdErrors) = SBOMComponentsWalker.GetComponents(Configuration.BuildComponentPath?.Value);

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
}
