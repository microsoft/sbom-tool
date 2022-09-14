using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Microsoft.Sbom.Parser
{
    internal class TestParser
    {
        private bool isFileArrayParsingStarted = false;
        private bool isPackageArrayParsingStarted = false;
        private JsonReaderState readerState;
        private byte[] buffer;

        public TestParser(int bufferSize = Constants.ReadBufferSize)
        {
            buffer = new byte[bufferSize];
        }

        public IEnumerable<SPDXPackage> GetPackages(Stream stream)
        {
            stream.Read(buffer);

            while (GetPackages(stream, out SPDXPackage sbomPackage) != 0)
            {
                yield return sbomPackage;
            }

            long GetPackages(Stream stream, out SPDXPackage sbomPackage)
            {
                var reader = new Utf8JsonReader(buffer, isFinalBlock: false, readerState);

                if (!isPackageArrayParsingStarted)
                {
                    ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                    isPackageArrayParsingStarted = true;
                }

                var parser = new SbomPackageParser(stream);
                var result = parser.GetSbomPackage(ref buffer, ref reader, out sbomPackage);

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

                if (!isFileArrayParsingStarted)
                {
                    ParserUtils.SkipFirstArrayToken(stream, ref buffer, ref reader);
                    isFileArrayParsingStarted = true;
                }

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
