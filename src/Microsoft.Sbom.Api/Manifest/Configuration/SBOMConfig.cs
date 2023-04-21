// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Common;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Manifest.Configuration;

/// <summary>
/// Represents a configuration object for a given SBOM Format. It holds all the 
/// relevant serializers and generation data for the given SBOM format.
/// </summary>
public class SbomConfig : ISbomConfig, IDisposable, IAsyncDisposable
{
    private Stream fileStream;
    private readonly IFileSystemUtils fileSystemUtils;

    public SbomConfig(IFileSystemUtils fileSystemUtils)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    /// <summary>
    /// Gets or sets absolute path of manifest json directory.
    /// </summary>
    public string ManifestJsonDirPath { get; set; }

    /// <summary>
    /// Gets or sets absolute path of the manfest json file.
    /// </summary>
    public string ManifestJsonFilePath { get; set; }

    /// <summary>
    /// Gets or sets the absolute path of the manifest json sha256 hash file.
    /// </summary>
    public string ManifestJsonFileSha256FilePath { get; set; }

    /// <summary>
    /// Gets or sets the absolute path of the signed catalog file.
    /// </summary>
    public string CatalogFilePath { get; set; }

    /// <summary>
    /// Gets or sets the absolute path of the build session information file.
    /// </summary>
    public string BsiFilePath { get; set; }

    /// <summary>
    /// Gets or sets derived manifestInfo or from configurations.
    /// </summary>
    public ManifestInfo ManifestInfo { get; set; }

    /// <summary>
    /// Gets or sets the metadata builder for this manifest format.
    /// </summary>
    public IMetadataBuilder MetadataBuilder { get; set; }

    /// <summary>
    /// Gets the generated manifest tool json serializer for this SBOM config.
    /// </summary>
    public IManifestToolJsonSerializer JsonSerializer { get; protected set; }

    /// <summary>
    /// Gets or sets records ids and generated package details for the current SBOM.
    /// </summary>
    public ISbomPackageDetailsRecorder Recorder { get; set; }

    public void StartJsonSerialization()
    {
        if (ManifestJsonDirPath == null)
        {
            throw new ArgumentNullException(nameof(ManifestJsonDirPath));
        }

        if (ManifestJsonFilePath == null)
        {
            throw new ArgumentNullException(nameof(ManifestJsonFilePath));
        }

        fileSystemUtils.CreateDirectory(ManifestJsonDirPath);
        fileStream = fileSystemUtils.OpenWrite(ManifestJsonFilePath);
        JsonSerializer = new ManifestToolJsonSerializer(fileStream);
    }

    #region Disposable implementation

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public async ValueTask DisposeAsync()
    {
        await DisposeAsyncCore();

        Dispose(disposing: false);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            (JsonSerializer as IDisposable)?.Dispose();
            (fileStream as IDisposable)?.Dispose();
        }

        fileStream = null;
        JsonSerializer = null;
    }

    protected virtual async ValueTask DisposeAsyncCore()
    {
        if (JsonSerializer is IAsyncDisposable jsonSerializerDisposable)
        {
            await jsonSerializerDisposable.DisposeAsync().ConfigureAwait(false);
        }
        else
        {
            JsonSerializer?.Dispose();
        }

        if (fileStream is IAsyncDisposable fileStreamDisposable)
        {
            await fileStreamDisposable.DisposeAsync().ConfigureAwait(false);
        }
        else
        {
            fileStream?.Dispose();
        }

        fileStream = null;
        JsonSerializer = null;
    }

    #endregion
}