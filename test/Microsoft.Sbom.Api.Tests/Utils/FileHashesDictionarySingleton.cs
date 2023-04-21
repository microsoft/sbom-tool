using Microsoft.Sbom.Api.Manifest.FileHashes;
using System;
using System.Collections.Concurrent;

namespace Microsoft.Sbom.Utils;

/// <summary>
/// Singleton object to encapsulate a <see cref="FileHashesDictionary"/> object.
/// </summary>
public sealed class FileHashesDictionarySingleton
{
    private FileHashesDictionary dictionary;

    private FileHashesDictionarySingleton() 
        => dictionary = new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>());

    private static readonly Lazy<FileHashesDictionarySingleton> Lazy = 
        new (() => new FileHashesDictionarySingleton());

    public static FileHashesDictionary Instance => Lazy.Value.dictionary;

    /// <summary>
    /// Resets the underlying dictionary.
    /// </summary>
    public static void Reset() 
        => Lazy.Value.dictionary = new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>());
}