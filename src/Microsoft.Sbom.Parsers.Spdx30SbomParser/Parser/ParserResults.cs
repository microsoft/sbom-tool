// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser;

using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

public class ParserResults
{
    public FormatEnforcedSPDX3 FormatEnforcedSPDX3Result { get; set; }

    public int FilesCount = 0;
    public int PackagesCount = 0;
    public int ReferencesCount = 0;
    public int RelationshipsCount = 0;
}
