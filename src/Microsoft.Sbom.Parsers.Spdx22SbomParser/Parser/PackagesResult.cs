// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

public record PackagesResult : ParserStateResult
{
    public PackagesResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
    }

    public IEnumerable<SPDXPackage> Packages => ((IEnumerable<object>)this.Result!).Select(r => (SPDXPackage)r);
}
