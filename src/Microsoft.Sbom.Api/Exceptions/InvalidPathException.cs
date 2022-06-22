// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions
{
    /// <summary>
    /// Thrown when the file path is invalid or inaccessible.
    /// </summary>
    [Serializable]
    public class InvalidPathException : Exception
    {
        public InvalidPathException()
        {
        }

        public InvalidPathException(string message)
            : base(message)
        {
        }

        public InvalidPathException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected InvalidPathException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}