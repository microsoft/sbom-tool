// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Entities.Output;

/// <summary>
/// Error container for validation errors.
/// </summary>
/// <typeparam name="T"></typeparam>
public class ErrorContainer<T>
{
    /// <summary>
    /// Gets or sets the total count of errors.
    /// </summary>
    public int Count { get; set; }

    /// <summary>
    /// Gets or sets the list of errors.
    /// </summary>
    public IList<T> Errors { get; set; }
}
