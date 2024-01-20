// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Output;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>
/// Builds a <see cref="MetadataBuilder"/> object for a given SBOM format.
/// </summary>
public class MetadataBuilderFactory : IMetadataBuilderFactory
{
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private readonly IRecorder recorder;
    private readonly IServiceProvider serviceProvider;

    public MetadataBuilderFactory(
        ManifestGeneratorProvider manifestGeneratorProvider,
        IRecorder recorder,
        IServiceProvider serviceProvider)
    {
        if (manifestGeneratorProvider is null)
        {
            throw new ArgumentNullException(nameof(manifestGeneratorProvider));
        }

        this.manifestGeneratorProvider = manifestGeneratorProvider;
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.serviceProvider = serviceProvider;
    }

    public IMetadataBuilder Get(ManifestInfo manifestInfo) => new MetadataBuilder(
        this.serviceProvider.GetRequiredService<ILogger<MetadataBuilder>>(),
        this.manifestGeneratorProvider,
        manifestInfo,
        this.recorder);
}
