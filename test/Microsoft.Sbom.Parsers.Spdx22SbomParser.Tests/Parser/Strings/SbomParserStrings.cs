using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Parser.Strings
{
    internal readonly struct SbomParserStrings
    {
        public const string JsonWithAll4Properties = @"{
            ""files"": [],
            ""packages"": [],
            ""relationships"": [],
            ""externalDocumentRefs"": []
            }";
    }
}
