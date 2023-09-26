// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Executors;

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
                        var manifestGenerator = manifestGeneratorProvider.Get(manifestInfo);
                        var generationResult = manifestGenerator.GenerateJsonDocument(relationships.Current);
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
