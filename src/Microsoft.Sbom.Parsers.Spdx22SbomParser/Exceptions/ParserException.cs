// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Exceptions;

/// <summary>
/// Thrown when the SPDX parser detects an error in the JSON file.
/// </summary>
public class ParserException : Exception
{
    public ParserException()
    {
    }

    public ParserException(string message)
        : base(message)
    {
    }

    public ParserException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
