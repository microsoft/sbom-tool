using Microsoft.Sbom.Contracts.Enums;
using System;

namespace Microsoft.Sbom.Contracts.Entities
{
    /// <summary>
    /// Represents a single file in a SBOM.
    /// </summary>
    public class FileEntity : Entity
    {
        /// <summary>
        /// The path of the file as included in the SBOM.
        /// </summary>
        public string Path { get; private set; }
        
        /// <nodoc />
        public FileEntity(string path, string id = null) : base(EntityType.File, id)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException($"'{nameof(path)}' cannot be null or empty.", nameof(path));
            }

            Path = path;
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return $"FileEntity (Path={Path}{(Id == null ? string.Empty : ", Id="+Id)})";
        }
    }
}
