// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// Compares two <see cref="ScannedComponent"/> objects to see if they represent the same underlying component.
    /// </summary>
    public class ScannedComponentEqualityComparer : IEqualityComparer<ScannedComponent>
    {
        public bool Equals([AllowNull] ScannedComponent scannedComponent1, [AllowNull] ScannedComponent scannedComponent2)
        {
            if (scannedComponent2 == null && scannedComponent1 == null)
                return true;
            else if (scannedComponent1 == null || scannedComponent2 == null)
                return false;
            else if (string.Equals(
                        scannedComponent1.Component.Id,
                        scannedComponent2.Component.Id, 
                        StringComparison.OrdinalIgnoreCase))
                return true;
            else
                return false;
        }

        public int GetHashCode([DisallowNull] ScannedComponent scannedComponent)
        {
            return scannedComponent.Component.Id.ToLower().GetHashCode();
        }
    }
}
