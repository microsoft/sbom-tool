// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

#nullable enable

public abstract class SbomParserTestsBase
{
    public ParserResults Parse(SPDXParser parser, Stream? stream = null, bool close = false)
    {
        var results = new ParserResults();

        ParserStateResult? result = null;
        do
        {
            result = parser.Next();

            if (close)
            {
                if (stream is not null)
                {
                    stream.Close();
                }
                else
                {
                    throw new NotImplementedException("Can't close a stream without the stream.");
                }
            }

            if (result is not null)
            {
                var enumerable = result.Result as IEnumerable<object>;
                var list = enumerable?.ToList();
                var count = list?.Count;
                switch (result.FieldName)
                {
                    case SPDXParser.FilesProperty:
                        results.Files = list?.Cast<SPDXFile>();
                        results.FilesCount = count;
                        break;
                    case SPDXParser.PackagesProperty:
                        results.Packages = list?.Cast<SPDXPackage>();
                        results.PackagesCount = count;
                        break;
                    case SPDXParser.ReferenceProperty:
                        results.References = list?.Cast<SpdxExternalDocumentReference>();
                        results.ReferencesCount = count;
                        break;
                    case SPDXParser.RelationshipsProperty:
                        results.Relationships = list?.Cast<SPDXRelationship>();
                        results.RelationshipsCount = count;
                        break;
                }
            }
        }
        while (result is not null);

        return results;
    }
}
