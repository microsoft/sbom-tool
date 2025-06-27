// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser;

/// <summary>
/// Implements <see cref="IMergeableContentProvider"/> for SPDX 2.2 files.
/// </summary>
public class MergeableContentProvider : IMergeableContentProvider
{
    private readonly IFileSystemUtils fileSystemUtils;

    public MergeableContentProvider(IFileSystemUtils fileSystemUtils)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    /// <summary>
    /// This provider supports only SPDX 2.2 files.
    /// </summary>
    public ManifestInfo ManifestInfo => Constants.Spdx22ManifestInfo;

    /// <summary>
    /// Implements <see cref="IMergeableContentProvider.TryGetContent(string, out MergeableContent)"/>.
    /// </summary>
    public bool TryGetContent(string filePath, out MergeableContent mergeableContent)
    {
        if (filePath is null)
        {
            throw new ArgumentNullException(nameof(filePath));
        }

        if (!fileSystemUtils.FileExists(filePath))
        {
            mergeableContent = null;
            return false;
        }

        using var stream = fileSystemUtils.OpenRead(filePath);

        if (stream == null)
        {
            mergeableContent = null;
            return false;
        }

        try
        {
            return GetMergeableContent(stream, out mergeableContent);
        }
        catch (Exception)
        {
            mergeableContent = null;
            return false;
        }
    }

    /// <summary>
    /// Core engine for converting the stream to the content.
    /// </summary>
    private bool GetMergeableContent(Stream stream, out MergeableContent mergeableContent)
    {
        // Skip sections that are expensive to parse and would require additional logic to properly ignore.
        var parser = new SPDXParser(stream, ["files", "externalDocumentRefs", "relationships"]);
        var packages = Enumerable.Empty<SbomPackage>();
        var relationships = Enumerable.Empty<SbomRelationship>();

        ParserStateResult result = null;
        do
        {
            result = parser.Next();
            if (result is not null)
            {
                switch (result)
                {
                    case PackagesResult packagesResult:
                        packages = ProcessPackages(packagesResult.Packages);
                        break;
                    default:
                        break;
                }
            }
        }
        while (result is not null);

        mergeableContent = new MergeableContent(packages, relationships);
        return true;
    }

    /// <summary>
    /// Process packages and return the collection of <see cref="SbomPackage"/> objects.
    /// </summary>
    private IEnumerable<SbomPackage> ProcessPackages(IEnumerable<SPDXPackage> spdxPackages)
    {
        var packages = new List<SbomPackage>();
        foreach (var spdxPackage in spdxPackages)
        {
            var sbomPackage = new SbomPackage
            {
                PackageName = spdxPackage.Name,
                PackageVersion = spdxPackage.VersionInfo,
                Id = spdxPackage.SpdxId,
                FilesAnalyzed = spdxPackage.FilesAnalyzed,
                LicenseInfo = new LicenseInfo
                {
                    Concluded = spdxPackage.LicenseConcluded,
                    Declared = spdxPackage.LicenseDeclared
                },
            };
            packages.Add(sbomPackage);
        }

        return packages;
    }
}
