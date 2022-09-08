using System;
using System.Runtime.Serialization;

namespace Microsoft.Sbom.Exceptions;

[Serializable]
public class ParserError : Exception
{
    public ParserError()
    {
    }

    public ParserError(string message)
        : base(message)
    {
    }

    public ParserError(string message, Exception innerException) 
        : base(message, innerException)
    {
    }

    protected ParserError(SerializationInfo info, StreamingContext context) 
        : base(info, context)
    {
    }
}
