// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Providers;

/// <summary>
/// Provides a stream of serialized Json for a given source, like packages or files.
/// </summary>
public interface ISourcesProvider
{
    /// <summary>
    /// Generate a <see cref="JsonDocWithSerializer"/> stream for all the sources for each of the required configuration.
    /// </summary>
    /// <param name="requiredConfigs">The configurations for which to generate serialized Json.</param>
    /// <returns></returns>
    (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) Get(IList<ISbomConfig> requiredConfigs);

    /// <summary>
    /// Returns true if this provider is suppored for the provided source.
    /// </summary>
    /// <param name="providerType">The type of the provider that is required.</param>
    /// <returns></returns>
    bool IsSupported(ProviderType providerType);
}