// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Exceptions;

internal class MissingHashValueException : Exception
{
    public MissingHashValueException()
    {
    }

    public MissingHashValueException(string message)
        : base(message)
    {
    }

    public MissingHashValueException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
