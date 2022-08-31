// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Config.Attributes
{
    /// <summary>
    /// Checks if the path specified by the string property is a valid directory, and 
    /// checks appropriate permissions for the directory.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    public sealed class DirectoryExistsAttribute : Attribute
    {
        /// <summary>
        /// Gets or sets the action for which this validation should run. Default is all.
        /// </summary>
        public ManifestToolActions ForAction { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether checks if the directory has read permissions, 'true' by default.
        /// </summary>
        public bool HasReadPermissions { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether checks if the directory has write permissions, 'false' by default.
        /// </summary>
        public bool HasWritePermissions { get; set; }

        public DirectoryExistsAttribute()
        {
            HasReadPermissions = true;
            HasWritePermissions = false;
            ForAction = ManifestToolActions.All;
        }
    }
}
