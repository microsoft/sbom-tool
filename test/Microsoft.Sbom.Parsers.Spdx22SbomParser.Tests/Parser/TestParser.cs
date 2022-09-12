using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Microsoft.Sbom.Parser
{
    internal class TestParser
    {
        private bool isFirstToken = true;
        private JsonReaderState readerState;
        private byte[] buffer = new byte[Constants.ReadBufferSize];

        public IEnumerable<SBOMFile> GetFiles(Stream stream)
        {        
            stream.Read(buffer);

            while (GetFiles(stream, out SBOMFile sbomFile) != 0)
            {
                yield return sbomFile;
            }

            long GetFiles(Stream stream, out SBOMFile sbomFile)
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (isFirstToken)
                {
                    // Ensure first value is an array and read that so that we are the { token.
                    ParserUtils.SkipNoneTokens(stream, ref buffer, ref reader);
                    ParserUtils.AssertTokenType(stream, ref buffer, ref reader, JsonTokenType.StartArray);
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);

                    isFirstToken = false;
                }

                Console.WriteLine($"String in buffer is: {Encoding.UTF8.GetString(buffer)}");

                var parser = new SbomFileParser(stream);
                var result = parser.GetSbomFile(ref buffer, ref reader, out sbomFile);

                // The caller always closes the ending }
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    ParserUtils.Read(stream, ref buffer, ref reader);
                    ParserUtils.GetMoreBytesFromStream(stream, ref buffer, ref reader);
                }

                readerState = reader.CurrentState;
                return result;
            }
        }
    }
}
