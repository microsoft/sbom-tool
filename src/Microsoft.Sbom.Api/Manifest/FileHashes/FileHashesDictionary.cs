using Microsoft.Sbom.Contracts;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Manifest.FileHashes
{
    public class FileHashesDictionary
    {
        private readonly ConcurrentDictionary<string, FileHashes> fileHashes;

        public FileHashesDictionary(ConcurrentDictionary<string, FileHashes> fileHashes)
        {
            this.fileHashes = fileHashes;
        }

        public void AddOnDiskHash(string filePath, Checksum checksum)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException($"'{nameof(filePath)}' cannot be null or whitespace.", nameof(filePath));
            }

            if (checksum is null)
            {
                throw new ArgumentNullException(nameof(checksum));
            }

            var fileHashOnDisk = new FileHashes
            {
                OnDiskHash = checksum,
                OnDiskHashPresent = true,
            };

            var shouldDeleteKey = false;

            var newValue = fileHashes.AddOrUpdate(filePath, fileHashOnDisk, (key, currentValue) =>
            {
                if (currentValue.OnDiskHashPresent == true)
                {
                    // Failure, we have discovered a duplicate key
                    throw new Exception($"Duplicate checksum entry for file {filePath} found on disk.");
                }

                currentValue.OnDiskHash = checksum;
                currentValue.OnDiskHashPresent = true;

                return currentValue;
            });

            if (shouldDeleteKey)
            {
                if (!fileHashes.TryRemove(new KeyValuePair<string, FileHashes>(filePath, newValue)))
                {
                    throw new Exception($"File {filePath} has hashes in both ");
                }
            }    
        }
    }
}
