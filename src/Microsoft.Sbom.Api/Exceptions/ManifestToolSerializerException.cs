// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when the manifest tool is unable to serialize the SBOM component.
/// </summary>
[Serializable]
public class ManifestToolSerializerException : Exception
{
    public ManifestToolSerializerException() { }

    public ManifestToolSerializerException(string message)
        : base(message) { }

    public ManifestToolSerializerException(string message, Exception inner)
        : base(message, inner) { }

#if NET8_0_OR_GREATER
    [Obsolete(DiagnosticId = "SYSLIB0051")] // SerializationInfo type is obsolete as of .NET8
#endif
    protected ManifestToolSerializerException(
        System.Runtime.Serialization.SerializationInfo info,
        System.Runtime.Serialization.StreamingContext context)
        : base(info, context) { }
}
