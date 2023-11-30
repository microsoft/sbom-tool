// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parser;

using System.Collections.Generic;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

public class ParserResults
{
    public IEnumerable<SPDXFile>? Files { get; set; }

    public IEnumerable<SPDXPackage>? Packages { get; set; }

    public IEnumerable<SpdxExternalDocumentReference>? References { get; set; }

    public IEnumerable<SPDXRelationship>? Relationships { get; set; }

    public int? FilesCount = null;
    public int? PackagesCount = null;
    public int? ReferencesCount = null;
    public int? RelationshipsCount = null;
}
