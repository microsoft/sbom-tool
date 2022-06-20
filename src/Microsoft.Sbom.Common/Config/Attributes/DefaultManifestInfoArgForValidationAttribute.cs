// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using ManifestInterface.Entities;
using System;

namespace Microsoft.Sbom.Common.Config.Attributes
{
    [AttributeUsage(AttributeTargets.Assembly)]
    public class DefaultManifestInfoArgForValidationAttribute : Attribute
    {
        /// <summary>
        /// The default value of the ManifestInfo to use in case of validation action
        /// where the user hasn't provided any parameter value.
        /// </summary>
        public ManifestInfo ManifestInfo { get; set; }

        public DefaultManifestInfoArgForValidationAttribute(string name, string version)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException($"'{nameof(name)}' cannot be null or empty.", nameof(name));
            }

            if (string.IsNullOrEmpty(version))
            {
                throw new ArgumentException($"'{nameof(version)}' cannot be null or empty.", nameof(version));
            }

            ManifestInfo = new ManifestInfo
            {
                Name = name,
                Version = version
            };
        }


    }
}
