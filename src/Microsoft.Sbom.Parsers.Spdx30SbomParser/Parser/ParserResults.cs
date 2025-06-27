// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser;

using System.Collections.Generic;
using Microsoft.Sbom.Common.Conformance;
using Microsoft.Sbom.Common.Spdx30Entities;

public class ParserResults
{
    public FormatEnforcedSPDX30 FormatEnforcedSPDX3Result { get; set; }

    public HashSet<InvalidElementInfo> InvalidConformanceElements { get; set; } = [];

    public int FilesCount = 0;
    public int PackagesCount = 0;
    public int ReferencesCount = 0;
    public int RelationshipsCount = 0;
}
