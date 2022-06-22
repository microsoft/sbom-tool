// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api
{
    /// <summary>
    /// Defines the exit code returned by the ManifestTool executable 
    /// </summary>
    public enum ExitCode
    {
        Success = 0,
        GeneralError = 1,
        WriteAccessError = 2
    }
}
