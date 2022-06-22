﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Manifest;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Takes a list of relationships and generates the SBOM JsonDocuments for each of the
    /// relationship.
    /// </summary>
    public class RelationshipGenerator
    {
        private readonly ManifestGeneratorProvider manifestGeneratorProvider;

        public RelationshipGenerator(ManifestGeneratorProvider manifestGeneratorProvider)
        {
            this.manifestGeneratorProvider = manifestGeneratorProvider ?? throw new ArgumentNullException(nameof(manifestGeneratorProvider));
        }

        public virtual ChannelReader<JsonDocument> Run(IEnumerator<Relationship> relationships, ManifestInfo manifestInfo)
        {
            var output = Channel.CreateUnbounded<JsonDocument>();

            Task.Run(async () =>
            {
                using (relationships)
                {
                    try
                    {
                        while (relationships.MoveNext())
                        {
                            IManifestGenerator manifestGenerator = manifestGeneratorProvider.Get(manifestInfo);
                            GenerationResult generationResult = manifestGenerator.GenerateJsonDocument(relationships.Current);
                            await output.Writer.WriteAsync(generationResult?.Document);
                        }
                    }
                    finally
                    {
                        output.Writer.Complete();
                    }
                }
            });

            return output;
        }
    }
}
