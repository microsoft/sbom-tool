// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

public record RelationshipsResult : ParserStateResult
{
    public RelationshipsResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
    }

    public IEnumerable<SPDXRelationship> Relationships => (IEnumerable<SPDXRelationship>)this.Result!;
}
