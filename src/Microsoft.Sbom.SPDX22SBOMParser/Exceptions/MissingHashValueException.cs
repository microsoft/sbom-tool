using System;
using System.Runtime.Serialization;

namespace Microsoft.SPDX22SBOMParser.Exceptions
{
    [Serializable]
    internal class MissingHashValueException : Exception
    {
        public MissingHashValueException()
        {
        }

        public MissingHashValueException(string message) : base(message)
        {
        }

        public MissingHashValueException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected MissingHashValueException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}