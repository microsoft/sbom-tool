// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when there is a problem in parsing the <see cref="IConfiguration"/>.
/// </summary>
[Serializable]
public class ConfigurationException : Exception
{
    public ConfigurationException()
    {
    }

    public ConfigurationException(string message)
        : base(message)
    {
    }

    public ConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

#if NET8_0_OR_GREATER
    [Obsolete(DiagnosticId = "SYSLIB0051")] // SerializationInfo type is obsolete as of .NET8
#endif
    protected ConfigurationException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
