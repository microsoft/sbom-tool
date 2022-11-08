// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using System.Runtime.InteropServices;

namespace Microsoft.Sbom.Api.SignValidator
{
    /// <summary>
    /// A NoOp sign validator that always returns true.
    /// </summary>
    public class NullSignValidator : ISignValidator
    {
        public OSPlatform SupportedPlatform => OSPlatform.Windows;

        public bool Validate()
        {
            return true;
        }
    }
}
