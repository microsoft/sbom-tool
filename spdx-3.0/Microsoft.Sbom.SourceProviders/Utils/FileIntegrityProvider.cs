using System.IO.Enumeration;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Utils;
internal class FileIntegrityProvider
{
    public static IList<IntegrityMethod>? Sha256IntegrityProvider(ref FileSystemEntry fileSystemEntry, ILogger logger)
    {
        using var hasher = SHA256.Create();
        using FileStream fileStream = System.IO.File.OpenRead(fileSystemEntry.ToFullPath());
        try
        {
            // Create a fileStream for the file.
            // Be sure it's positioned to the beginning of the stream.
            fileStream.Position = 0;

            // Compute the hash of the fileStream.
            byte[] hashValueBytes = hasher.ComputeHash(fileStream);
            var hashValue = BitConverter.ToString(hashValueBytes).Replace("-", string.Empty).ToLowerInvariant();

            return new List<IntegrityMethod>() { new Hash(Spdx3_0.Core.Enums.HashAlgorithm.Sha256, hashValue) };
        }
        catch (IOException e)
        {
            logger.LogError(exception: e, message: "IO Exception while generating hash for file {filePath}: {exceptionMessage}", fileSystemEntry.ToFullPath(), e.Message);
            return null;
        }
        catch (UnauthorizedAccessException e)
        {
            logger.LogError(exception: e, message: "Unauthorized to access file {filePath} to generate hash: {exceptionMessage}", fileSystemEntry.ToFullPath(), e.Message);
            return null;
        }
    }
}
