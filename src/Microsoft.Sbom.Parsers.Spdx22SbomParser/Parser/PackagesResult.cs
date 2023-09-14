// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using JsonAsynchronousNodeKit;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

public record PackagesResult : ParserStateResult
{
    public PackagesResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
    }

    public IEnumerable<SPDXPackage> Packages => (IEnumerable<SPDXPackage>)this.Result!;
}
