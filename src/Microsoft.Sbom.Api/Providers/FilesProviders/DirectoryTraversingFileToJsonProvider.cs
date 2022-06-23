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
    /// Traverse a given folder recursively to generate a list of files to be serialized.
    /// </summary>
    public class DirectoryTraversingFileToJsonProvider : PathBasedFileToJsonProviderBase
    {
        [Inject]
        public DirectoryWalker DirectoryWalker { get; set; }

        public override bool IsSupported(ProviderType providerType)
        {
            if (providerType == ProviderType.Files)
            {
                // This is the last sources provider we should use, if no other sources have been provided by the user.
                // Thus, this condition should be to check that all the remaining configurations for file inputs are null.
                if (string.IsNullOrWhiteSpace(Configuration.BuildListFile?.Value) && Configuration.FilesList?.Value == null)
                {
                    Log.Debug($"Using the {nameof(DirectoryTraversingFileToJsonProvider)} provider for the files workflow.");
                    return true;
                }
            }

            return false;
        }

        protected override (ChannelReader<string> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel()
        {
            return DirectoryWalker.GetFilesRecursively(Configuration.BuildDropPath?.Value);
        }

        protected override (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) WriteAdditionalItems(IList<ISbomConfig> requiredConfigs)
        {
            return (null, null);
        }
    }
}
