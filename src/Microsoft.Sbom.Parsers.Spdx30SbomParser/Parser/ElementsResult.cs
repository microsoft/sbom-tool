// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities;

namespace Microsoft.Sbom.Parser;

public record ElementsResult : ParserStateResult
{
    public ElementsResult(ParserStateResult result)
        : base(result.FieldName, result.Result, result.ExplicitField, result.YieldReturn)
    {
        this.Elements = new List<Element>();
        this.Files = new List<File>();
        this.Packages = new List<Package>();
        this.SpdxDocuments = new List<SpdxDocument>();
        this.CreationInfos = new List<CreationInfo>();
        this.InvalidComplianceStandardElements = new HashSet<string>();
        this.ElementsSpdxIdList = new HashSet<string>();

        this.FilesCount = 0;
        this.PackagesCount = 0;
        this.ReferencesCount = 0;
        this.RelationshipsCount = 0;
    }

    public List<Element> Elements { get; set; }

    public List<File> Files { get; set; }

    public List<Package> Packages { get; set; }

    public List<SpdxDocument> SpdxDocuments { get; set; }

    public List<CreationInfo> CreationInfos { get; set; }

    /// <summary>
    /// SPDX ID's of invalid elements that don't comply with the given compliance standard.
    /// If SPDX ID is missing, the JSON object will be used to identify the element.
    /// </summary>
    public HashSet<string> InvalidComplianceStandardElements { get; set; }

    /// <summary>
    /// SPDX ID's of elements used for deduplication when parsing an SBOM.
    /// </summary>
    public HashSet<string> ElementsSpdxIdList { get; set; }

    public int FilesCount { get; set; }

    public int PackagesCount { get; set; }

    public int ReferencesCount { get; set; }

    public int RelationshipsCount { get; set; }
}
