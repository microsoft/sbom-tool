// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

public class NoAssertionElement : Element
{
    public NoAssertionElement()
    {
        Name = "NoAssertion";
        SpdxId = "SPDXRef-NoAssertion";
        Type = nameof(Element);
    }
}
