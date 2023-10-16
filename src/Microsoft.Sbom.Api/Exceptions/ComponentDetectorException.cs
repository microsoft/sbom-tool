// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Api.Exceptions;

/// <summary>
/// Thrown when we encounter a problem while running the component detector.
/// </summary>
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
}
