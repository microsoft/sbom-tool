// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when we are provided a hash algorithm value that is currently not supported by our service.
/// </summary>
public class UnsupportedHashAlgorithmException : Exception
{
    public UnsupportedHashAlgorithmException()
    {
    }

    public UnsupportedHashAlgorithmException(string message)
        : base(message)
    {
    }

    public UnsupportedHashAlgorithmException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
