// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Common.Spdx30Entities.Enums;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities.Enums;
using Microsoft.Sbom.Utils;
using SbomEntities = Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils.Comparer;

/// <summary>
/// Finds the content differences between an SPDX 2.2 document and an SPDX 3.0 document.
/// </summary>
public class SbomEqualityComparer
{
    private JsonSerializerOptions serializerOptions = new JsonSerializerOptions
    {
        Converters = { new ElementSerializer() },
    };

    private readonly JsonElement spdx22Json;
    private readonly JsonElement spdx30Json;

    private readonly SbomFileComparer sbomFileComparer;
    private readonly SbomPackageComparer sbomPackageComparer;
    private readonly SbomRelationshipComparer sbomRelationshipComparer;
    private readonly SbomReferenceComparer sbomReferenceComparer;

    public SbomEqualityComparer(JsonElement spdx22Json, JsonElement spdx30Json)
    {
        this.spdx22Json = spdx22Json;
        this.spdx30Json = spdx30Json;
        this.sbomFileComparer = new SbomFileComparer();
        this.sbomPackageComparer = new SbomPackageComparer();
        this.sbomRelationshipComparer = new SbomRelationshipComparer();
        this.sbomReferenceComparer = new SbomReferenceComparer();
    }

    public bool DocumentsEqual()
    {
        var spdx22Files = GetSpdx22Files(spdx22Json);
        var spdx22Packages = GetSpdx22Packages(spdx22Json);
        var spdx22ExternalDocumentRefs = GetSpdx22ExternalDocumentRefs(spdx22Json);
        var spdx22Relationships = GetSpdx22Relationships(spdx22Json);

        var graphArray = spdx30Json.GetProperty(Constants.SPDXGraphHeaderName);
        var elements = graphArray.Deserialize<List<Element>>(this.serializerOptions);

        var spdx30Files = elements.OfType<File>().ToList();
        var spdx30Packages = elements.OfType<Package>().ToList();
        var spdx30ExternalDocumentRefs = elements.OfType<ExternalMap>().ToList();
        var spdx30Relationships = elements.OfType<Relationship>().ToList();

        var externalDocRefsEqual = CheckExternalDocRefs(spdx22ExternalDocumentRefs, spdx30ExternalDocumentRefs);
        if (!externalDocRefsEqual)
        {
            return externalDocRefsEqual;
        }

        var relationshipsEqual = CheckRelationships(spdx22Relationships, spdx30Relationships);
        if (!relationshipsEqual)
        {
            return relationshipsEqual;
        }

        var filesEqual = CheckFiles(spdx22Files, spdx30Files, elements, spdx30Relationships);
        if (!filesEqual)
        {
            return filesEqual;
        }

        var packagesEqual = CheckPackages(spdx22Packages, spdx30Packages, elements, spdx30Relationships);
        if (!packagesEqual)
        {
            return packagesEqual;
        }

        return true;
    }

    internal bool CheckFiles(List<SPDXFile> spdx22Files, List<File> spdx30Files, List<Element> spdx30Elements, List<Relationship> relationships)
    {
        if (spdx22Files.Count != spdx30Files.Count)
        {
            return false;
        }

        var spdx22InternalSbomFileInfos = ConvertToSbomFiles(spdx22Files);
        var spdx30InternalSbomFileInfos = ConvertToSbomFiles(spdx30Files, spdx30Elements, relationships);

        return spdx22InternalSbomFileInfos.SetEquals(spdx30InternalSbomFileInfos);
    }

    internal bool CheckPackages(List<SPDXPackage> spdx22Packages, List<Package> spdx30Packages, List<Element> spdx30Elements, List<Relationship> relationships)
    {
        if (spdx22Packages.Count != spdx30Packages.Count)
        {
            return false;
        }

        var spdx22InternalSbomPackages = ConvertToSbomPackages(spdx22Packages);
        var spdx30InternalSbomPackages = ConvertToSbomPackages(spdx30Packages, spdx30Elements, relationships);

        return spdx22InternalSbomPackages.SetEquals(spdx30InternalSbomPackages);
    }

    internal bool CheckRelationships(List<SPDXRelationship> spdx22Relationships, List<Relationship> spdx30Relationships)
    {
        // Filtering out relationships that describe license information since SPDX 2.2 does not support these relationship types.
        // The license relationships are linked to files and packages when comparing the two SBOMs in the CheckFiles and CheckPackages methods.
        var spdx30RelationshipsNotRelatedtoLicenses = spdx30Relationships.Where(
            element => element.RelationshipType != RelationshipType.HAS_CONCLUDED_LICENSE
            && element.RelationshipType != RelationshipType.HAS_DECLARED_LICENSE)
            .ToList();

        if (spdx22Relationships.Count != spdx30RelationshipsNotRelatedtoLicenses.Count)
        {
            return false;
        }

        var spdx22InternalRelationships = ConvertToRelationships(spdx22Relationships);
        var spdx30InternalRelationships = ConvertToRelationships(spdx30RelationshipsNotRelatedtoLicenses);

        return spdx22InternalRelationships.SetEquals(spdx30InternalRelationships);
    }

    internal bool CheckExternalDocRefs(List<SpdxExternalDocumentReference> spdx22ExternalDocumentRefs, List<ExternalMap> spdx30ExternalDocumentRefs)
    {
        if (spdx22ExternalDocumentRefs.Count != spdx30ExternalDocumentRefs.Count)
        {
            return false;
        }

        var spdx22InternalExternalDocRefs = ConvertToSbomReferences(spdx22ExternalDocumentRefs);
        var spdx30InternalExternalDocRefs = ConvertToSbomReferences(spdx30ExternalDocumentRefs);

        return spdx22InternalExternalDocRefs.SetEquals(spdx30InternalExternalDocRefs);
    }

    private HashSet<SbomFile> ConvertToSbomFiles(List<SPDXFile> files)
    {
        var sbomFiles = new HashSet<SbomFile>(sbomFileComparer);

        foreach (var file in files)
        {
            sbomFiles.Add(file.ToSbomFile());
        }

        return sbomFiles;
    }

    private HashSet<SbomFile> ConvertToSbomFiles(List<File> files, List<Element> spdx30Elements, List<Relationship> relationships)
    {
        var sbomFiles = new HashSet<SbomFile>(sbomFileComparer);

        foreach (var file in files)
        {
            sbomFiles.Add(file.ToSbomFile(spdx30Elements, relationships));
        }

        return sbomFiles;
    }

    private HashSet<SbomPackage> ConvertToSbomPackages(List<SPDXPackage> packages)
    {
        var sbomPackages = new HashSet<SbomPackage>(sbomPackageComparer);

        foreach (var package in packages)
        {
            sbomPackages.Add(package.ToSbomPackage());
        }

        return sbomPackages;
    }

    private HashSet<SbomPackage> ConvertToSbomPackages(List<Package> packages, List<Element> spdx30Elements, List<Relationship> relationships)
    {
        var sbomPackages = new HashSet<SbomPackage>(sbomPackageComparer);

        foreach (var package in packages)
        {
            sbomPackages.Add(package.ToSbomPackage(spdx30Elements, relationships));
        }

        return sbomPackages;
    }

    private HashSet<SbomRelationship> ConvertToRelationships(List<SPDXRelationship> relationships)
    {
        var sbomRelationships = new HashSet<SbomRelationship>(sbomRelationshipComparer);

        foreach (var relationship in relationships)
        {
            // For these special cases, swap the source and target element IDs and change the 2.2 relationshipType to the logical equivalent in 3.0.
            // This is because SPDX 3.0 does not support the following relationship types.
            if (relationship.RelationshipType == SPDXRelationshipType.PREREQUISITE_FOR.ToString())
            {
                relationship.RelationshipType = RelationshipType.HAS_PREREQUISITE.ToString();
                (relationship.SourceElementId, relationship.TargetElementId) = (relationship.TargetElementId, relationship.SourceElementId);
            }
            else if (relationship.RelationshipType == SPDXRelationshipType.DESCRIBED_BY.ToString())
            {
                relationship.RelationshipType = SbomEntities.RelationshipType.DESCRIBES.ToString();
                (relationship.SourceElementId, relationship.TargetElementId) = (relationship.TargetElementId, relationship.SourceElementId);
            }
            else if (relationship.RelationshipType == SPDXRelationshipType.PATCH_FOR.ToString())
            {
                relationship.RelationshipType = RelationshipType.PATCHED_BY.ToString();
                (relationship.SourceElementId, relationship.TargetElementId) = (relationship.TargetElementId, relationship.SourceElementId);
            }

            sbomRelationships.Add(relationship.ToSbomRelationship());
        }

        return sbomRelationships;
    }

    private HashSet<SbomRelationship> ConvertToRelationships(List<Relationship> relationships)
    {
        var sbomRelationships = new HashSet<SbomRelationship>(sbomRelationshipComparer);

        foreach (var relationship in relationships)
        {
            sbomRelationships.UnionWith(relationship.ToSbomRelationship());
        }

        return sbomRelationships;
    }

    private HashSet<SbomReference> ConvertToSbomReferences(List<SpdxExternalDocumentReference> externalDocRefs)
    {
        var sbomReferences = new HashSet<SbomReference>(sbomReferenceComparer);

        foreach (var externalDocRef in externalDocRefs)
        {
            sbomReferences.Add(externalDocRef.ToSbomReference());
        }

        return sbomReferences;
    }

    private HashSet<SbomReference> ConvertToSbomReferences(List<ExternalMap> externalDocRefs)
    {
        var sbomReferences = new HashSet<SbomReference>(sbomReferenceComparer);

        foreach (var externalDocRef in externalDocRefs)
        {
            sbomReferences.Add(externalDocRef.ToSbomReference());
        }

        return sbomReferences;
    }

    private List<SPDXFile> GetSpdx22Files(JsonElement spdx22Json)
    {
        return spdx22Json.GetProperty("files")
            .EnumerateArray()
            .Select(element => JsonSerializer.Deserialize<SPDXFile>(element.GetRawText()))
            .ToList();
    }

    private List<SPDXPackage> GetSpdx22Packages(JsonElement spdx22Json)
    {
        return spdx22Json.GetProperty("packages")
            .EnumerateArray()
            .Select(element => JsonSerializer.Deserialize<SPDXPackage>(element.GetRawText()))
            .ToList();
    }

    private List<SpdxExternalDocumentReference> GetSpdx22ExternalDocumentRefs(JsonElement spdx22Json)
    {
        return spdx22Json.GetProperty("externalDocumentRefs")
            .EnumerateArray()
            .Select(element => JsonSerializer.Deserialize<SpdxExternalDocumentReference>(element.GetRawText()))
            .ToList();
    }

    private List<SPDXRelationship> GetSpdx22Relationships(JsonElement spdx22Json)
    {
        return spdx22Json.GetProperty("relationships")
            .EnumerateArray()
            .Select(element => JsonSerializer.Deserialize<SPDXRelationship>(element.GetRawText()))
            .ToList();
    }
}
