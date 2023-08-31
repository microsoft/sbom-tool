﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Exception during argument validation used to indicate when we don't have access to a path passed as argument.
/// </summary>
[Serializable]
public class ClearlyDefinedResponseNotSuccesfulException : Exception
{
    public ClearlyDefinedResponseNotSuccesfulException(string message)
        : base(message)
    {
    }

}