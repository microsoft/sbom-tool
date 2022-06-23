// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Api.Converters;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Executors;
using Ninject;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;

namespace Microsoft.Sbom.Api.Providers.FilesProviders
{
    /// <summary>
    /// Provider for external document reference which leverage component detection tool
    /// to discover SBOM files.
    /// </summary>
    public class CGScannedExternalDocumentReferenceFileProvider : PathBasedFileToJsonProviderBase
    {
        [Inject]
        public ComponentToExternalReferenceInfoConverter ComponentToExternalReferenceInfoConverter { get; set; }

        [Inject]
        public ExternalReferenceInfoToPathConverter ExternalReferenceInfoToPathConverter { get; set; }

        [Inject]
        public ExternalDocumentReferenceWriter ExternalDocumentReferenceWriter { get; set; }

        [Inject]
        public SBOMComponentsWalker SBOMComponentsWalker { get; set; }

        public override bool IsSupported(ProviderType providerType)
        {
            if (providerType == ProviderType.Files)
            {
                Log.Debug($"Using the {nameof(CGScannedExternalDocumentReferenceFileProvider)} provider for the files workflow.");
                return true;
            }

            return false;
        }

        protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
        {
            var (sbomOutput, cdErrors) = SBOMComponentsWalker.GetComponents(Configuration.BuildComponentPath?.Value);
            IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();

            if (cdErrors.TryRead(out ComponentDetectorException e))
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
}
