// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes
{
    /// <summary>
    /// Checks if the numeric value is equal to or between the min and max range.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
    public sealed class IntRangeAttribute : Attribute
    {
        /// <summary>
        /// Execute this validation only for the given action. Default is all.
        /// </summary>
        public ManifestToolActions ForAction { get; set; }

        /// <summary>
        /// The inclusive minimum value of this integer.
        /// </summary>
        public int MinRange { get; }

        /// <summary>
        /// The inclusive maximum value of this integer.
        /// </summary>
        public int MaxRange { get; }

        public IntRangeAttribute(int MinRange, int MaxRange)
        {
            this.MinRange = MinRange;
            this.MaxRange = MaxRange;
            ForAction = ManifestToolActions.All;
        }
    }
}
