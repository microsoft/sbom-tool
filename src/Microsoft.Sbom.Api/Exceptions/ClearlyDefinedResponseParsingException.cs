// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Exception thrown while parsing a response from ClearlyDefined.
/// </summary>
[Serializable]
public class ClearlyDefinedResponseParsingException : Exception
{
    public ClearlyDefinedResponseParsingException(string message)
        : base(message)
    {
    }
}
