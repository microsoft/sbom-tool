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
