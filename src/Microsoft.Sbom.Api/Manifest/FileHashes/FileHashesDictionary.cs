// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;

namespace Microsoft.Sbom.Api.Manifest.FileHashes;

/// <summary>
/// A container for a concurrent dictionary that is used to store <see cref="FileHashes"/>
/// used in validation.
/// </summary>
public class FileHashesDictionary
{
    public ConcurrentDictionary<string, FileHashes> FileHashes { get; private set; }

    public FileHashesDictionary(ConcurrentDictionary<string, FileHashes> fileHashes)
    {
        FileHashes = fileHashes;
    }
}