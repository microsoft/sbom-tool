// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Exception thrown when response from ClearlyDefined is not successful.
/// </summary>
[Serializable]
public class ClearlyDefinedResponseNotSuccessfulException : Exception
{
    public ClearlyDefinedResponseNotSuccessfulException(string message)
        : base(message)
    {
    }
}
