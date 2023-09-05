// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when manifest folder already exists in output path.
/// </summary>
public class ManifestFolderExistsException : Exception
{
    public ManifestFolderExistsException()
    {
    }

    public ManifestFolderExistsException(string message)
        : base(message)
    {
    }

    public ManifestFolderExistsException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
