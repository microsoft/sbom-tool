// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Ninject.Activation;
using PowerArgs;
using System;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Manifest
{
    /// <summary>
    /// Provides the <see cref="ManifestConfig"/> by deriving manifest configs for the operation.
    /// </summary>
    public class ManifestConfigProvider : Provider<ISbomConfig>
    {
        private readonly IManifestConfigHandler[] manifestConfigHandlers;
        
        
        public ManifestConfigProvider(IManifestConfigHandler[] manifestConfigHandlers)
        {
            this.manifestConfigHandlers = manifestConfigHandlers ?? throw new ArgumentNullException(nameof(manifestConfigHandlers));
        }

        /// <summary>
        /// Provides the <see cref="ManifestConfig"/> object for the given SBOM format.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected override ISbomConfig CreateInstance(IContext context)
        {
            // Get the first usable handler.
            foreach (var configHandler in manifestConfigHandlers)
            {
                if (configHandler.TryGetManifestConfig(out ISbomConfig sbomConfig))
                {
                    return sbomConfig;
                }
            }

            throw new ValidationArgException($"Unable to find a valid SBOM parser for the current SBOM format.");
        }
    }
}
