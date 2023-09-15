// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.Serialization;

namespace JsonAsynchronousNodeKit.Exceptions;

/// <summary>
/// Thrown when the SPDX parser detects an error in the JSON file.
/// </summary>
[Serializable]
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

    protected ParserException(SerializationInfo info, StreamingContext context)
        : base(info, context)
    {
    }
}
