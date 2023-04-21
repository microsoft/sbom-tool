// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Serilog;

namespace Microsoft.Sbom.Api.Output;

/// <summary>
/// Builds a <see cref="MetadataBuilder"/> object for a given SBOM format.
/// </summary>
public class MetadataBuilderFactory : IMetadataBuilderFactory
{
    private readonly ILogger logger;
    private readonly ManifestGeneratorProvider manifestGeneratorProvider;
    private readonly IRecorder recorder;

    public MetadataBuilderFactory(
        ILogger logger,
        ManifestGeneratorProvider manifestGeneratorProvider,
        IRecorder recorder)
    {
        if (logger is null)
        {
            throw new ArgumentNullException(nameof(logger));
        }

        if (manifestGeneratorProvider is null)
        {
            throw new ArgumentNullException(nameof(manifestGeneratorProvider));
        }

        this.logger = logger;
        this.manifestGeneratorProvider = manifestGeneratorProvider;
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
    }

    public IMetadataBuilder Get(ManifestInfo manifestInfo)
    {
        return new MetadataBuilder(logger, manifestGeneratorProvider, manifestInfo, recorder);
    }
}