// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Contracts.Enums;
using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Contracts
{
    /// <summary>
    /// Represents a checksum for a file or package.
    /// </summary>
    public class Checksum : IEquatable<Checksum>
    {
        /// <summary>
        /// Gets or sets the name of the hashing algorithm used to generate this hash.
        /// ex. <see cref="AlgorithmName.SHA256"/>.
        /// </summary>
        public AlgorithmName Algorithm { get; set; }

        /// <summary>
        /// Gets or sets the generated hash value.
        /// </summary>
        public string ChecksumValue { get; set; }

        public override bool Equals(object obj)
        {
            return Equals(obj as Checksum);
        }

        public bool Equals(Checksum other)
        {
            return other != null &&
                   Algorithm.Equals(other.Algorithm) &&
                   ChecksumValue == other.ChecksumValue;
        }

        public override int GetHashCode()
        {
            int hashCode = 1457973397;
            hashCode = (hashCode * -1521134295) + Algorithm.GetHashCode();
            hashCode = (hashCode * -1521134295) + EqualityComparer<string>.Default.GetHashCode(ChecksumValue);
            return hashCode;
        }

        public static bool operator ==(Checksum left, Checksum right)
        {
            return EqualityComparer<Checksum>.Default.Equals(left, right);
        }

        public static bool operator !=(Checksum left, Checksum right)
        {
            return !(left == right);
        }
    }
}
