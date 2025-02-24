// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Entities;

namespace Microsoft.Sbom.Api.Manifest.FileHashes;

/// <summary>
/// Represents a file with its hashes for 2 file locations, on disk and inside SBOM.
/// </summary>
public class FileHashes
{
    /// <summary>
    /// The hash of the file that was calculated based on the on disk file.
    /// </summary>
    public Checksum OnDiskHash { get; private set; }

    /// <summary>
    /// The hash of the file that was read from the SBOM file.
    /// </summary>
    public Checksum SbomFileHash { get; private set; }

    /// <summary>
    /// The enum flag that shows hashes for what location are already in this object.
    /// If both hashes are present this location should be equal to <see cref="FileLocation.All"/>,
    /// if none of the hashes are present it should be equal to <see cref="FileLocation.None"/>.
    /// </summary>
    public FileLocation FileLocation { get; private set; } = FileLocation.None;

    /// <summary>
    /// Get the hash for the location specified by <paramref name="fileLocation"/>
    /// </summary>
    /// <param name="fileLocation"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    public Checksum GetHash(FileLocation fileLocation) => fileLocation switch
    {
        FileLocation.OnDisk => OnDiskHash,
        FileLocation.InSbomFile => SbomFileHash,
        _ => throw new Exception("Unknown file location type for SBOM file."),
    };

    /// <summary>
    /// Set the hash for the location specified by <paramref name="fileLocation"/>
    /// </summary>
    /// <param name="fileLocation"></param>
    /// <param name="checksum"></param>
    public void SetHash(FileLocation fileLocation, Checksum checksum)
    {
        switch (fileLocation)
        {
            case FileLocation.OnDisk:
                OnDiskHash = checksum;
                break;
            case FileLocation.InSbomFile:
                SbomFileHash = checksum;
                break;
            default:
                break;
        }

        FileLocation |= fileLocation;
    }
}
