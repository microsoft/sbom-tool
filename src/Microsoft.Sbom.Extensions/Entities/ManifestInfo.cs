// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Sbom.Extensions.Entities
{
    /// <summary>
    /// Defines a manifest name and version.
    /// </summary>
    public class ManifestInfo : IEquatable<ManifestInfo>
    {
        /// <summary>
        /// Gets or sets the name of the manifest.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the version of the manifest.
        /// </summary>
        public string Version { get; set; }

        /// <summary>
        /// Parses the manifest info from a string
        /// The format is <name>:<version>
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1629:Documentation text should end with a period", 
            Justification = "Code element in comment.")]
        public static ManifestInfo Parse(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException($"The manifest info string is empty");
            }

            var values = value.Split(':');
            if (values == null || values.Length != 2)
            {
                throw new ArgumentException($"The manifest info string is not formatted correctly. The correct format is <name>:<version>.");
            }

            return new ManifestInfo
            {
                Name = values[0],
                Version = values[1]
            };
        }

        public override bool Equals(object other)
        {
            return Equals(other as ManifestInfo);
        }

        public static bool operator ==(ManifestInfo obj1, ManifestInfo obj2)
        {
            if (ReferenceEquals(obj1, obj2))
            {
                return true;
            }

            if (obj1 is null || obj2 is null)
            {
                return false;
            }

            return obj1.Equals(obj2);
        }

        public static bool operator !=(ManifestInfo obj1, ManifestInfo obj2) => !(obj1 == obj2);

        public override int GetHashCode()
        {
            int hashCode = 2112831277;
            hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(Name);
            hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(Version);
            return hashCode;
        }

        public bool Equals(ManifestInfo other)
        {
            return Name.ToLowerInvariant() == other.Name.ToLowerInvariant() &&
                   Version.ToLowerInvariant() == other.Version.ToLowerInvariant();
        }

        public override string ToString()
        {
            return $"{Name}:{Version}";
        }
    }
}
