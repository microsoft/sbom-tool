// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;

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
                results.FormatEnforcedSPDX3Result ??= new FormatEnforcedSPDX30();
                switch (result.FieldName)
                {
                    case Constants.SPDXContextHeaderName:
                        results.FormatEnforcedSPDX3Result.Context = (result as ContextsResult)?.Contexts.FirstOrDefault();
                        break;
                    case Constants.SPDXGraphHeaderName:
                        var elementsResult = (ElementsResult)result;
                        results.FormatEnforcedSPDX3Result.Graph = elementsResult.Elements;
                        results.FilesCount = elementsResult.FilesCount;
                        results.PackagesCount = elementsResult.PackagesCount;
                        results.RelationshipsCount = elementsResult.RelationshipsCount;
                        results.ReferencesCount = elementsResult.ReferencesCount;
                        results.InvalidConformanceStandardElements = elementsResult.InvalidConformanceStandardElements;
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
