using System;

namespace Microsoft.Sbom.Api.Exceptions
{
    /// <summary>
    /// Thrown when manifest folder already exists in output path.
    /// </summary>
    public class ManifestFolderExistsException : Exception
    {
        public ManifestFolderExistsException()
        {
        }

        public ManifestFolderExistsException(string message)
            : base(message)
        {
        }

        public ManifestFolderExistsException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}