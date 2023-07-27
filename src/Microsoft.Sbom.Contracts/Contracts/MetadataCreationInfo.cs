// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;

/// <summary>
/// An object that represents the creation information of an SPDX document.
/// </summary>
public class MetadataCreationInfo
{
    /// <summary>
    /// The <see cref="DateTime"/> the SPDX document was created.
    /// </summary>
    public DateTime Created { get; set; }

    /// <summary>
    /// A list of key value pairs that represent the SPDX document creators.
    /// </summary>
    public IEnumerable<string> Creators { get; set; }
}
