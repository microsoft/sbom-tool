// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions
{
    /// <summary>
    /// Thrown when the generated hash is invalid.
    /// </summary>
    [Serializable]
    public class HashGenerationException : Exception
    {
        public HashGenerationException()
        {
        }

        public HashGenerationException(string message) : base(message)
        {
        }

        public HashGenerationException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected HashGenerationException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
