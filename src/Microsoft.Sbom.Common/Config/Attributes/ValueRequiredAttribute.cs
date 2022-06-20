﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes
{
    /// <summary>
    /// Checks if the value of the property is not null or empty.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
    public sealed class ValueRequiredAttribute : Attribute
    {
        /// <summary>
        /// Execute this validation only for the given action. Default is all.
        /// </summary>
        public ManifestToolActions ForAction { get; set; }

        public ValueRequiredAttribute()
        {
            ForAction = ManifestToolActions.All;
        }
    }
}
