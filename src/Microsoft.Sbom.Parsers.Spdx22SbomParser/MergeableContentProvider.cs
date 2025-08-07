// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parser;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;
using Serilog;

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser;

/// <summary>
/// Implements <see cref="IMergeableContentProvider"/> for SPDX 2.2 files.
/// </summary>
public class MergeableContentProvider : IMergeableContentProvider
{
    private const string DependsOn = "DEPENDS_ON";

    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILogger logger;

    public MergeableContentProvider(IFileSystemUtils fileSystemUtils, ILogger logger)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
            logger.Debug($"File '{filePath}' does not exist.");
            mergeableContent = null;
            return false;
        }

        using var stream = fileSystemUtils.OpenRead(filePath);

        if (stream == null)
        {
            logger.Debug($"Unable to open stream for file '{filePath}'.");
            mergeableContent = null;
            return false;
        }

        try
        {
            logger.Debug($"Attempting to parse SPDX file at '{filePath}'.");
            return GetMergeableContent(stream, out mergeableContent);
        }
        catch (Exception)
        {
            logger.Debug($"Failed to parse SPDX file at '{filePath}'. It may not be a valid SPDX 2.2 file.");
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
        var parser = new SPDXParser(stream, new[] { "files", "externalDocumentRefs" });
        IList<SbomPackage> packages = new List<SbomPackage>();
        IList<SbomRelationship> relationships = new List<SbomRelationship>();

        ParserStateResult result = null;
        do
        {
            result = parser.Next();
            if (result is not null)
            {
                switch (result)
                {
                    case PackagesResult packagesResult:
                        packages = ProcessPackages(packagesResult.Packages.ToList());  // ToList() ensures correct parsing of the data
                        break;
                    case RelationshipsResult relationshipsResult:
                        relationships = ProcessRelationships(relationshipsResult.Relationships.ToList());  // ToList() ensures correct parsing of the data
                        break;
                    default:
                        break;
                }
            }
        }
        while (result is not null);

        mergeableContent = CreateRemappedMergeableContent(packages, relationships);
        return true;
    }

    /// <summary>
    /// Process packages and return the collection of <see cref="SbomPackage"/> objects.
    /// </summary>
    private IList<SbomPackage> ProcessPackages(IReadOnlyList<SPDXPackage> spdxPackages)
    {
        var packages = new List<SbomPackage>();
        foreach (var spdxPackage in spdxPackages)
        {
            var sbomPackage = spdxPackage.ToSbomPackage();
            packages.Add(sbomPackage);
        }

        return packages;
    }

    private IList<SbomRelationship> ProcessRelationships(IReadOnlyList<SPDXRelationship> spdxRelationships)
    {
        var relationships = new List<SbomRelationship>();

        foreach (var spdxRelationship in spdxRelationships)
        {
            if (IsDependsOnRelationship(spdxRelationship))
            {
                var relationship = new SbomRelationship
                {
                    SourceElementId = spdxRelationship.SourceElementId,
                    TargetElementId = spdxRelationship.TargetElementId,
                    RelationshipType = DependsOn, // Force output consistency
                };
                relationships.Add(relationship);
            }
        }

        return relationships;
    }

    private static bool IsDependsOnRelationship(SPDXRelationship spdxRelationship)
    {
        // Include both "DEPENDS_ON" and "DEPENDSON" to cover variations in SPDX files, and ignore case.
        return spdxRelationship.RelationshipType.Equals("DEPENDS_ON", StringComparison.InvariantCultureIgnoreCase) ||
               spdxRelationship.RelationshipType.Equals("DEPENDSON", StringComparison.InvariantCultureIgnoreCase);
    }

    /// <summary>
    /// Remaps the root package ID, updates relationships accordingly, then creates a new <see cref="MergeableContent"/> object.
    /// </summary>
    private MergeableContent CreateRemappedMergeableContent(IList<SbomPackage> packages, IList<SbomRelationship> relationships)
    {
        var mappedRootPackageId = GetAdjustedRootPackageId(packages);

        AdjustRootPackageRelationships(relationships, mappedRootPackageId);

        logger.Debug($"MergeableContent includes {packages.Count} package(s) and {relationships.Count} relationship(s).");

        return new MergeableContent(packages, relationships);
    }

    private string GetAdjustedRootPackageId(IList<SbomPackage> packages)
    {
        foreach (var package in packages)
        {
            if (package.Id == Constants.RootPackageIdValue)
            {
                package.Id = null;
                var newSpdxId = CommonSPDXUtils.GenerateSpdxPackageId(package);
                package.Id = newSpdxId;
                logger.Debug($"Remapped root package ID from '{Constants.RootPackageIdValue}' to '{newSpdxId}'");
                return newSpdxId;
            }
        }

        throw new InvalidDataException("No root package found in the SPDX document.");
    }

    private void AdjustRootPackageRelationships(IList<SbomRelationship> relationships, string mappedRootPackageId)
    {
        // Update relationships where the source is the root package.
        foreach (var relationship in relationships)
        {
            if (relationship.SourceElementId == Constants.RootPackageIdValue)
            {
                // Update the source element ID to the remapped root package ID.
                logger.Verbose($"Remapped root package dependency on '{relationship.TargetElementId}'");
                relationship.SourceElementId = mappedRootPackageId;
            }
        }

        // Make the output root depend on the remapped root.
        var newRootRelationship = new SbomRelationship
        {
            SourceElementId = Constants.RootPackageIdValue,
            TargetElementId = mappedRootPackageId,
            RelationshipType = DependsOn, // Force output consistency
        };
        relationships.Add(newRootRelationship);
        logger.Debug($"Added new root relationship from '{Constants.RootPackageIdValue}' to '{mappedRootPackageId}'");
    }
}
