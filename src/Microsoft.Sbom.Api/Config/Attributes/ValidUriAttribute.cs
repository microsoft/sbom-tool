// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Config.Attributes
{
    /// <summary>
    /// Validate if the property value is a valid URI.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
    public sealed class ValidUriAttribute : Attribute
    {
        /// <summary>
        /// Gets or sets execute this validation only for the given action. Default is all.
        /// </summary>
        public ManifestToolActions ForAction { get; set; }

        /// <summary>
        /// Gets or sets the type of URI the value should be.
        /// </summary>
        public UriKind UriKind { get; set; }

        public ValidUriAttribute()
        {
            ForAction = ManifestToolActions.Generate;
        }
    }
}
