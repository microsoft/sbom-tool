// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Exceptions
{
    [Serializable]
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

        protected MissingHashValueException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}