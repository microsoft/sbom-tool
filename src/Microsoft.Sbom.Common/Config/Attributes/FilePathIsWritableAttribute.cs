﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes
{
    /// <summary>
    /// Checks if the filepath specified by the string parameter is writable by the current user.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    public sealed class FilePathIsWritableAttribute : Attribute
    {
        /// <summary>
        /// Gets or sets the action for which this validation should run. Default is all.
        /// </summary>
        public ManifestToolActions ForAction { get; set; }

        public FilePathIsWritableAttribute()
        {
            ForAction = ManifestToolActions.All;
        }
    }
}
