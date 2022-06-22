// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Api.Exceptions
{
    /// <summary>
    /// Thrown when we are unable to find a generator to serialize the SBOM
    /// </summary>
    [Serializable]
    public class MissingGeneratorException : Exception
    {
        public MissingGeneratorException()
        {
        }

        public MissingGeneratorException(string message)
            : base(message)
        {
        }

        public MissingGeneratorException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected MissingGeneratorException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
