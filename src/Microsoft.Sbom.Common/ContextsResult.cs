// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.JsonAsynchronousNodeKit;

namespace Microsoft.Sbom.Common;

public record ContextsResult : ParserStateResult
{
    public ContextsResult(ParserStateResult result, List<string> contexts)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
        Contexts = contexts;
    }

    public IEnumerable<string> Contexts { get; set; }
}
