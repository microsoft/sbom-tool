// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Manifest.FileHashes;
using Ninject.Activation;
using System.Collections.Concurrent;

namespace Microsoft.Sbom.Api.Manifest
{
    /// <summary>
    /// Provides a <see cref="FileHashesDictionary"/> to be used for validation.
    /// </summary>
    public class FileHashesDictionaryProvider : Provider<FileHashesDictionary>
    {
        protected override FileHashesDictionary CreateInstance(IContext context)
            => new (new ConcurrentDictionary<string, FileHashes.FileHashes>());
    }
}
