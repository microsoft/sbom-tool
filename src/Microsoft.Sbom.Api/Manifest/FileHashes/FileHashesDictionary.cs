// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;

namespace Microsoft.Sbom.Api.Manifest.FileHashes
{
    public class FileHashesDictionary
    {
        public ConcurrentDictionary<string, FileHashes> FileHashes { get; private set; }

        public FileHashesDictionary(ConcurrentDictionary<string, FileHashes> fileHashes)
        {
            FileHashes = fileHashes;
        }
    }
}
