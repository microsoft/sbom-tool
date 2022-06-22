using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Microsoft.Sbom.Api.Tests
{
    internal class TestUtils
    {
        public static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}
