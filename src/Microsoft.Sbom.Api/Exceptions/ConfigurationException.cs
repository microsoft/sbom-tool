// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when there is a problem in parsing the <see cref="IConfiguration"/>.
/// </summary>
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
}
