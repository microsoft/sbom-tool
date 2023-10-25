// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using Microsoft.Sbom.Api.Manifest.FileHashes;

namespace Microsoft.Sbom.Utils;

/// <summary>
/// Singleton object to encapsulate a <see cref="FileHashesDictionary"/> object. Only used for testing.
/// </summary>
public sealed class FileHashesDictionarySingleton
{
    private FileHashesDictionary dictionary;

    /// <summary>
    /// Create a case insensitive dictionary for tests.
    /// </summary>
    private FileHashesDictionarySingleton()
        => dictionary = new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>(StringComparer.InvariantCultureIgnoreCase));

    private static readonly Lazy<FileHashesDictionarySingleton> Lazy =
        new(() => new FileHashesDictionarySingleton());

    public static FileHashesDictionary Instance => Lazy.Value.dictionary;

    /// <summary>
    /// Resets the underlying dictionary.
    /// </summary>
    public static void Reset()
        => Lazy.Value.dictionary = new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>(StringComparer.InvariantCultureIgnoreCase));
}
