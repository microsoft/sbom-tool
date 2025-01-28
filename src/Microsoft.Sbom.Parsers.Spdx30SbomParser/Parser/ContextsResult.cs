// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.JsonAsynchronousNodeKit;

namespace Microsoft.Sbom.Parser;

public record ContextsResult : ParserStateResult
{
    public ContextsResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
    }

    public IEnumerable<string> Contexts => ((IEnumerable<string>)this.Result!).Select(r => r);
}
