// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Sbom.Contracts
{
    /// <summary>
    /// Represents the specification of the SBOM.
    /// For ex. SPDX 2.2.
    /// </summary>
    public class SBOMSpecification : IEquatable<SBOMSpecification>
    {
        /// <summary>
        /// Gets the name of the SBOM specification.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the version of the SBOM specification.
        /// </summary>
        public string Version { get; private set; }

        public SBOMSpecification(string name, string version)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            if (string.IsNullOrWhiteSpace(version))
            {
                throw new ArgumentException($"'{nameof(version)}' cannot be null or empty.", nameof(version));
            }

            Name = name;
            Version = version;
        }

        /// <summary>
        /// Parse the given string into a <see cref="SBOMSpecification"/> object.
        /// </summary>
        /// <param name="value">The string representation of the SBOM.</param>
        /// <returns>A SBOMSpecification object.</returns>
        /// <example>spdx:2.2.</example>
        public static SBOMSpecification Parse(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException($"The SBOM specification string is empty");
            }

            var values = value.Split(':');
            if (values == null
                || values.Length != 2
                || values.Any(v => string.IsNullOrWhiteSpace(v)))
            {
                throw new ArgumentException($"The SBOM specification string is not formatted correctly. The correct format is <name>:<version>.");
            }

            return new SBOMSpecification(values[0], values[1]);
        }

        public override string ToString()
        {
            return $"{Name}:{Version}";
        }

        public override bool Equals(object obj) => this.Equals(obj as SBOMSpecification);

        public bool Equals(SBOMSpecification other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            // If run-time types are not exactly the same, return false.
            if (this.GetType() != other.GetType())
            {
                return false;
            }

            // Return true if the fields match.
            return Name.ToLowerInvariant() == other.Name.ToLowerInvariant() &&
                   Version.ToLowerInvariant() == other.Version.ToLowerInvariant();
        }

        public override int GetHashCode()
        {
            int hashCode = 2112831277;
            hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(Name);
            hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(Version);
            return hashCode;
        }

        public static bool operator ==(SBOMSpecification lhs, SBOMSpecification rhs)
        {
            if (lhs is null)
            {
                if (rhs is null)
                {
                    return true;
                }

                // Only the left side is null.
                return false;
            }

            // Equals handles case of null on right side.
            return lhs.Equals(rhs);
        }

        public static bool operator !=(SBOMSpecification lhs, SBOMSpecification rhs) => !(lhs == rhs);
    }
}
