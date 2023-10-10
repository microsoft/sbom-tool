// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when the manifest tool cannot find a signature validator for the current
/// operating system.
/// </summary>
[Serializable]
public class SignValidatorNotFoundException : Exception
{
    public SignValidatorNotFoundException()
    {
    }

    public SignValidatorNotFoundException(string message)
        : base(message)
    {
    }

    public SignValidatorNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

#if NET8_0_OR_GREATER
    [Obsolete(DiagnosticId = "SYSLIB0051")] // SerializationInfo type is obsolete as of .NET8
#endif
    protected SignValidatorNotFoundException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
