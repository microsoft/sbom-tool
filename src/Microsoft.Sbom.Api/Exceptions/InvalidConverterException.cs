// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when the instantiated <see cref="IPackageInfoConverter"/>
/// cannot convert the <see cref="Microsoft.VisualStudio.Services.Governance.ComponentDetection.TypedComponent"/>.
/// </summary>
/// <remarks>
/// Thrown out of public classes implementing IPackageInfoConverter so it must also be public.
/// <remarks>
[Serializable]
public class InvalidConverterException : Exception
{
    public InvalidConverterException()
    {
    }

    public InvalidConverterException(string message)
        : base(message)
    {
    }

    public InvalidConverterException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    protected InvalidConverterException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
