// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

public record ElementsResult : ParserStateResult
{
    public ElementsResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
    }

    public IEnumerable<Element> Elements { get; set; }

    public IEnumerable<File> Files { get; set; }

    public int FilesCount { get; set; }

    public int PackagesCount { get; set; }

    public int ReferencesCount { get; set; }

    public int RelationshipsCount { get; set; }
}
