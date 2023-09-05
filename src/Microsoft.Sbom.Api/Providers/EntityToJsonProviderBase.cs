// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Providers;

using Microsoft.Extensions.Logging;

/// <summary>
/// The base class for all providers. Defines the basic workflow for a entity (file or package).
/// </summary>
/// <typeparam name="T"></typeparam>
public abstract class EntityToJsonProviderBase<T> : ISourcesProvider
{
    /// <summary>
    /// Gets or sets the configuration that is used to generate the SBOM.
    /// </summary>
    public IConfiguration Configuration { get; }

    /// <summary>
    /// Gets or sets provides utilities for splitting and merging channel streams.
    /// </summary>
    public ChannelUtils ChannelUtils { get; }

    public ILogger<EntityToJsonProviderBase<T>> Log { get; }

    public EntityToJsonProviderBase(IConfiguration configuration, ChannelUtils channelUtils, ILogger<EntityToJsonProviderBase<T>> logger)
    {
        Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        ChannelUtils = channelUtils ?? throw new ArgumentNullException(nameof(channelUtils));
        Log = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Generate a <see cref="JsonDocWithSerializer"/> stream for all the entities for each of the required configuration.
    /// </summary>
    /// <param name="requiredConfigs">The configurations for which to generate serialized Json.</param>
    /// <returns></returns>
    public (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) Get(IList<ISbomConfig> requiredConfigs)
    {
        if (requiredConfigs is null)
        {
            throw new ArgumentNullException(nameof(requiredConfigs));
        }

        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();
        IList<ChannelReader<JsonDocWithSerializer>> jsonDocResults =
            new List<ChannelReader<JsonDocWithSerializer>>();

        var (sources, sourceErrors) = GetSourceChannel();
        errors.Add(sourceErrors);

        Log.LogDebug($"Splitting the workflow into {Configuration.Parallelism.Value} threads.");
        var splitSourcesChannels = ChannelUtils.Split(sources, Configuration.Parallelism.Value);

        this.Log.LogDebug("Running the generation workflow ...");

        foreach (var sourceChannel in splitSourcesChannels)
        {
            var (jsonResults, jsonErrors) = ConvertToJson(sourceChannel, requiredConfigs);

            jsonDocResults.Add(jsonResults);
            errors.Add(jsonErrors);
        }

        // Write out additional items if any.
        var (additionalResults, additionalErrors) = WriteAdditionalItems(requiredConfigs);
        if (additionalResults != null)
        {
            jsonDocResults.Add(additionalResults);
        }

        if (additionalErrors != null)
        {
            errors.Add(additionalErrors);
        }

        return (ChannelUtils.Merge(jsonDocResults.ToArray()), ChannelUtils.Merge(errors.ToArray()));
    }

    /// <summary>
    /// Should return true only if the provider type is supported.
    /// </summary>
    /// <param name="providerType"></param>
    /// <returns></returns>
    public abstract bool IsSupported(ProviderType providerType);

    /// <summary>
    /// Get a channel reader for type <see cref="T"/> that will give us a stream of objects to process.
    /// </summary>
    /// <returns></returns>
    protected abstract (ChannelReader<T> entities, ChannelReader<FileValidationResult> errors) GetSourceChannel();

    /// <summary>
    /// Given a channel of type <see cref="T"/> return a channel of serialized SBOM Json for the objects.
    /// </summary>
    /// <param name="sourceChannel"></param>
    /// <param name="requiredConfigs"></param>
    /// <returns></returns>
    protected abstract (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
        ConvertToJson(ChannelReader<T> sourceChannel, IList<ISbomConfig> requiredConfigs);

    /// <summary>
    /// Return any additional Json objects for the given entity.
    /// </summary>
    /// <param name="requiredConfigs"></param>
    /// <returns></returns>
    protected abstract (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors)
        WriteAdditionalItems(IList<ISbomConfig> requiredConfigs);
}
