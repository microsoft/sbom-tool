// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.Sbom.Extensions
{
    /// <summary>
    /// Validates the given manifest.json using the platform specific sign verification mechanism.
    /// </summary>
    public interface ISignValidator
    {
        /// <summary>
        /// The OS Platform that this validator supports, ex. Windows or Linux.
        /// </summary>
        public OSPlatform SupportedPlatform { get; }

        /// <summary>
        /// Validates the given manifest.json using the platform specific sign verification mechanism.
        /// </summary>
        /// <returns>true if valid, false otherwise.</returns>
        bool Validate();
    }
}
