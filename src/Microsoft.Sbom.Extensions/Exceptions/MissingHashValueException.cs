﻿using System;
using System.Runtime.Serialization;

namespace ManifestInterface.Exceptions
{
    /// <summary>
    /// Thrown when a required hash value for a package or file is missing.
    /// </summary>
    [Serializable]
    public class MissingHashValueException : Exception
    {
        public MissingHashValueException() { }
        public MissingHashValueException(string message) : base(message) { }
        public MissingHashValueException(string message, Exception inner) : base(message, inner) { }
        protected MissingHashValueException(
          SerializationInfo info,
          StreamingContext context) : base(info, context) { }
    }
}
