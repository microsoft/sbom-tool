using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Moq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Sbom.Utils
{
    /// <summary>
    /// Singleton object to encapsulate a <see cref="FileHashesDictionary"/> object.
    /// </summary>
    public sealed class FileHashesDictionarySingleton
    {
        private readonly FileHashesDictionary dictionary;

        private FileHashesDictionarySingleton()
        {
            dictionary = new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>());
        }

        private static readonly Lazy<FileHashesDictionarySingleton> Lazy = 
            new (() => new FileHashesDictionarySingleton());

        public static FileHashesDictionary Instance
        {
            get
            {
                return Lazy.Value.dictionary;
            }
        }
    }
}
