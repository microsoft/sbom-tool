// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;

namespace Microsoft.Sbom.Common;

/// <summary>
/// Wrapper interface for System.Environment to allow for testing.
/// </summary>
public interface IEnvironmentWrapper
{
    /// <summary>
    /// Method to call System.Environment.GetEnvironmentVariables.
    /// </summary>
    /// <returns> A dictionary of available environment variables. </returns>
    IDictionary GetEnvironmentVariables();
}