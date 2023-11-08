// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

public record class ExternalDocumentReferencesResult : ParserStateResult
{
    public ExternalDocumentReferencesResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
    }

    public IEnumerable<SpdxExternalDocumentReference> References => ((IEnumerable<object>)this.Result!).Select(r => (SpdxExternalDocumentReference)r);
}
