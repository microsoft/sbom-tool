// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Extensions;

/// <summary>
/// Provides a list of configs for all the SBOM formats that need to be generated.
/// We might need to generate more than one SBOM for backward compatibility.
/// </summary>
public interface ISbomConfigProvider : IDisposable, IAsyncDisposable, IInternalMetadataProvider
{
    /// <summary>
    /// Get the ISbomConfig object for the given format specificed in manifestInfo.
    /// Throws if the specified format does not exist.
    /// </summary>
    /// <param name="manifestInfo"></param>
    /// <returns></returns>
    ISbomConfig Get(ManifestInfo manifestInfo);

    /// <summary>
    /// Get the ISbomConfig object for the given format specificed in manifestInfo.
    /// </summary>
    /// <param name="manifestInfo"></param>
    /// <returns></returns>
    bool TryGet(ManifestInfo manifestInfo, out ISbomConfig sbomConfig);

    /// <summary>
    /// Gets a list of the <see cref="ManifestInfo"/>s that are included in the 
    /// SbomConfigProvider object.
    /// </summary>
    /// <returns></returns>
    IEnumerable<ManifestInfo> GetManifestInfos();

    /// <summary>
    /// Starts the JSON serialization of all the included ISbomConfig objects. This
    /// returns a <see cref="IDisposable"/> object that is used to clean up the JSON streams.
    /// </summary>
    /// <returns></returns>
    IDisposable StartJsonSerialization();

    /// <summary>
    /// Starts the JSON serialization of all the included ISbomConfig objects asynchronously. 
    /// This returns a <see cref="IAsyncDisposable"/> object that is used to clean up the JSON streams.
    /// </summary>
    /// <returns></returns>
    IAsyncDisposable StartJsonSerializationAsync();
       
    /// <summary>
    /// Helper method to operate an action on each included configs.
    /// </summary>
    /// <param name="action">The action to perform on the config.</param>
    void ApplyToEachConfig(Action<ISbomConfig> action);
}