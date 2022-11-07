// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Entities
{
    [Flags]
    public enum FileLocation
    {
        None,
        OnDisk,
        InSbomFile,
        All = OnDisk | InSbomFile,
    }
}
