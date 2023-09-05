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
using Serilog;

namespace Microsoft.Sbom.Api.Providers.FilesProviders;

/// <summary>
/// An abstract base class for all files providers. This class defines the main workflow for files generation, which all
/// inheriting classes can modify by overriding the abstract methods.
/// </summary>
/// <typeparam name="T">The type of the files channel that is used by the provider.</typeparam>
public abstract class FileToJsonProviderBase<T> : ISourcesProvider
{
    private readonly IConfiguration configuration;

    private readonly ILogger log;

    private readonly ChannelUtils channelUtils;

    public FileToJsonProviderBase(IConfiguration configuration, ILogger log, ChannelUtils channelUtils)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.channelUtils = channelUtils ?? throw new ArgumentNullException(nameof(channelUtils));
    }

    public (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) Get(IList<ISbomConfig> requiredConfigs)
    {
        IList<ChannelReader<FileValidationResult>> errors = new List<ChannelReader<FileValidationResult>>();
        IList<ChannelReader<JsonDocWithSerializer>> jsonDocResults =
            new List<ChannelReader<JsonDocWithSerializer>>();

        var (files, dirErrors) = GetFilesChannel();
        errors.Add(dirErrors);

        log.Debug($"Splitting the workflow into {configuration.Parallelism.Value} threads.");
        var splitFilesChannels = channelUtils.Split(files, configuration.Parallelism.Value);

        log.Debug("Running the files generation workflow ...");
        foreach (var fileChannel in splitFilesChannels)
        {
            var (jsonDoc, convertErrors) = ConvertToJson(fileChannel, requiredConfigs);

            errors.Add(convertErrors);
            jsonDocResults.Add(jsonDoc);
        }

        return (channelUtils.Merge(jsonDocResults.ToArray()), channelUtils.Merge(errors.ToArray()));
    }

    /// <summary>
    /// Get a channel reader for type <see cref="T"/> that will give us a stream of file objects to process.
    /// </summary>
    /// <returns></returns>
    protected abstract (ChannelReader<T> files, ChannelReader<FileValidationResult> errors) GetFilesChannel();

    /// <summary>
    /// Given the files channel of type <see cref="T"/> return a channel of serialized SBOM Json for the file.
    /// </summary>
    /// <param name="files"></param>
    /// <param name="requiredConfigs"></param>
    /// <returns></returns>
    protected abstract (ChannelReader<JsonDocWithSerializer> files, ChannelReader<FileValidationResult> errors)
        ConvertToJson(ChannelReader<T> files, IList<ISbomConfig> requiredConfigs);

    /// <summary>
    /// Should return true only if the provider type is supported.
    /// </summary>
    /// <param name="providerType"></param>
    /// <returns></returns>
    public abstract bool IsSupported(ProviderType providerType);
}
