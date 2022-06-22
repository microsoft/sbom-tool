// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions
{
    /// <summary>
    /// Thrown when we are provided a hash algorithm value that is currently not supported by our service.
    /// </summary>
    [Serializable]
    public class UnsupportedHashAlgorithmException : Exception
    {
        public UnsupportedHashAlgorithmException()
        {
        }

        public UnsupportedHashAlgorithmException(string message)
            : base(message)
        {
        }

        public UnsupportedHashAlgorithmException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected UnsupportedHashAlgorithmException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
