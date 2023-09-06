// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config;

[Flags]
public enum ManifestToolActions
{
    None = 0,
    Validate = 1,
    Generate = 2,

    All = Validate | Generate
}
