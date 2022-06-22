// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Ninject;
using System.Collections.Generic;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Manifest.Configuration;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Providers.FilesProviders
{
    /// <summary>
    /// Provider for external document reference file supported only when 
    /// ExternalDocumentReferenceListFile is provided in the generation arguments
    /// </summary>
    public class ExternalDocumentReferenceFileProvider : PathBasedFileToJsonProviderBase
    {
        [Inject]
        public FileListEnumerator ListWalker { get; set; }

        public override bool IsSupported(ProviderType providerType)
        {
            if (providerType == ProviderType.Files && !string.IsNullOrWhiteSpace(Configuration.ExternalDocumentReferenceListFile?.Value))
            {
                Log.Debug($"Using the {nameof(ExternalDocumentReferenceFileProvider)} provider for the files workflow.");
                return true;
            }

            return false;
        }

        protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors)  GetSourceChannel()
        {
            if(Configuration.ExternalDocumentReferenceListFile?.Value == null)
            {
                var emptyList = Channel.CreateUnbounded<string>();
                emptyList.Writer.Complete();
                var errors = Channel.CreateUnbounded<FileValidationResult>();
                errors.Writer.Complete();
                return (emptyList, errors);
            }
            return ListWalker.GetFilesFromList(Configuration.ExternalDocumentReferenceListFile.Value);
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
        {
            return (null, null);
        }
    }
}
