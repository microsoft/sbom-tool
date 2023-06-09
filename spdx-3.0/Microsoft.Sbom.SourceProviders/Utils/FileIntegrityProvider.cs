using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Entities;

namespace Microsoft.Sbom.Utils;
internal class FileIntegrityProvider
{
    public static async Task<IList<FileHash>?> Sha256IntegrityProvider(Stream stream, ILogger logger)
    {
        try
        {
            using var hasher = SHA256.Create();
            var hash = await Task.Run(() => hasher.ComputeHash(stream));

            return new List<FileHash>()
            {
                new FileHash("Sha256", BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant()),
            };
        }
        catch (ObjectDisposedException e)
        {
            logger.LogError(exception: e, message: "Unable to generate hash for file as the stream is closed.");
            throw;
        }
    }
}
