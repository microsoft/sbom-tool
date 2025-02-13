// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

#nullable enable

public abstract class SbomParserTestsBase
{
    public ParserResults Parse(SPDX30Parser parser, Stream? stream = null, bool close = false)
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

            if (result is not null && result.Result is not null)
            {
                results.FormatEnforcedSPDX3Result ??= new FormatEnforcedSPDX3();
                switch (result.FieldName)
                {
                    case SPDX30Parser.ContextProperty:
                        results.FormatEnforcedSPDX3Result.Context = (result as ContextsResult)?.Contexts.FirstOrDefault();
                        break;
                    case SPDX30Parser.GraphProperty:
                        var elementsResult = (ElementsResult)result;
                        results.FormatEnforcedSPDX3Result.Graph = elementsResult.Elements;
                        results.FilesCount = elementsResult.FilesCount;
                        results.PackagesCount = elementsResult.PackagesCount;
                        results.RelationshipsCount = elementsResult.RelationshipsCount;
                        results.ReferencesCount = elementsResult.ReferencesCount;
                        break;
                    default:
                        Console.WriteLine($"Unrecognized FieldName: {result.FieldName}");
                        break;
                }
            }
        }
        while (result is not null);

        return results;
    }
}
