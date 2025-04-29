// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Common.ConformanceStandard;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;

namespace Microsoft.Sbom.Common;

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
        this.InvalidConformanceStandardElements = new HashSet<InvalidElementInfo>();
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
    /// Invalid elements that don't comply with the given compliance standard.
    /// </summary>
    public HashSet<InvalidElementInfo> InvalidConformanceStandardElements { get; set; }

    /// <summary>
    /// SPDX ID's of elements used for deduplication when parsing an SBOM.
    /// </summary>
    public HashSet<string> ElementsSpdxIdList { get; set; }

    public int FilesCount { get; set; }

    public int PackagesCount { get; set; }

    public int ReferencesCount { get; set; }

    public int RelationshipsCount { get; set; }
}
