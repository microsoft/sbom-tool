﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Contracts.Entities
{
    /// <summary>
    /// Represents a single package in a SBOM.
    /// </summary>
    public class PackageEntity : Entity
    {
        /// <summary>
        /// Gets the name of the package.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the version of the package.
        /// </summary>
        public string Version { get; private set; }

        /// <summary>
        /// Gets the path where the package was found.
        /// </summary>
        public string Path { get; private set; }

        /// <nodoc />
        public PackageEntity(string name, string version = null, string path = null, string id = null)
            : base(EntityType.Package, id)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            Name = name;
            Version = version;
            Path = path;
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return $"PackageEntity (Id={Id}, Name={Name}, Version={Version}, Path={Path}";
        }
    }
}
