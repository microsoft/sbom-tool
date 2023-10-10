// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when we encounter a problem while running the component detector.
/// </summary>
[Serializable]
public class ComponentDetectorException : Exception
{
    public ComponentDetectorException()
    {
    }

    public ComponentDetectorException(string message)
        : base(message)
    {
    }

    public ComponentDetectorException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

#if NET8_0_OR_GREATER
    [Obsolete(DiagnosticId = "SYSLIB0051")] // SerializationInfo type is obsolete as of .NET8
#endif
    protected ComponentDetectorException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
