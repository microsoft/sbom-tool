// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Tools.Tests.Utils;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.Sbom.Utils;
using File = System.IO.File;
#pragma warning disable IDE0001 // Simplify Names
using Spdx30Entities = Microsoft.Sbom.Common.Spdx30Entities;
#pragma warning restore IDE0001 // Simplify Names

/// <summary>
/// Finds the differences between an SPDX 2.2 document and an SPDX 3.0 document.
/// </summary>
internal class SbomEqualityComparer
{
    private JsonSerializerOptions serializerOptions = new JsonSerializerOptions
    {
        Converters = { new ElementSerializer() },
    };

    private readonly string spdx22FilePath;
    private readonly string spdx30FilePath;

    public SbomEqualityComparer(string spdx22FilePath, string spdx30FilePath)
    {
        this.spdx22FilePath = spdx22FilePath;
        this.spdx30FilePath = spdx30FilePath;
    }

    public bool DocumentsEqual()
    {
        var spdx22Json = ReadJsonFile(spdx22FilePath);
        var spdx30Json = ReadJsonFile(spdx30FilePath);

        var spdx22Files = GetSpdx22Files(spdx22Json);
        var spdx22Packages = GetSpdx22Packages(spdx22Json);
        var spdx22ExternalDocumentRefs = GetSpdx22ExternalDocumentRefs(spdx22Json);
        var spdx22Relationships = GetSpdx22Relationships(spdx22Json);

        var graphArray = spdx30Json.GetProperty("graph");
        var elements = JsonSerializer.Deserialize<List<Element>>(graphArray, this.serializerOptions);

        var spdx30Files = elements.OfType<Spdx30Entities.File>().ToList();
        var spdx30Packages = elements.OfType<Package>().ToList();
        var spdx30ExternalDocumentRefs = elements.OfType<ExternalMap>().ToList();
        var spdx30Relationships = GetSpdx30Relationships(elements);

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

    private bool CheckFiles(List<SPDXFile> spdx22Files, List<Spdx30Entities.File> spdx30Files, List<Element> spdx30Elements, List<Spdx30Entities.Relationship> relationships)
    {
        if (spdx22Files.Count != spdx30Files.Count)
        {
            return false;
        }

        var spdx22InternalSbomFileInfos = ConvertToSbomFiles(spdx22Files);
        var spdx30InternalSbomFileInfos = ConvertToSbomFiles(spdx30Files, spdx30Elements, relationships);

        return spdx22InternalSbomFileInfos.SetEquals(spdx30InternalSbomFileInfos);
    }

    private bool CheckPackages(List<SPDXPackage> spdx22Packages, List<Package> spdx30Packages, List<Element> spdx30Elements, List<Spdx30Entities.Relationship> relationships)
    {
        if (spdx22Packages.Count != spdx30Packages.Count)
        {
            return false;
        }

        var spdx22InternalSbomPackages = ConvertToSbomPackages(spdx22Packages);
        var spdx30InternalSbomPackages = ConvertToSbomPackages(spdx30Packages, spdx30Elements, relationships);

        return spdx22InternalSbomPackages.SetEquals(spdx30InternalSbomPackages);
    }

    private bool CheckRelationships(List<SPDXRelationship> spdx22Relationships, List<Spdx30Entities.Relationship> spdx30Relationships)
    {
        if (spdx22Relationships.Count != spdx30Relationships.Count)
        {
            return false;
        }

        var spdx22InternalRelationships = ConvertToRelationships(spdx22Relationships);
        var spdx30InternalRelationships = ConvertToRelationships(spdx30Relationships);

        return spdx22InternalRelationships.SetEquals(spdx30InternalRelationships);
    }

    private bool CheckExternalDocRefs(List<SpdxExternalDocumentReference> spdx22ExternalDocumentRefs, List<ExternalMap> spdx30ExternalDocumentRefs)
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
        var sbomFiles = new HashSet<SbomFile>();

        foreach (var file in files)
        {
            sbomFiles.Add(file.ToSbomFile());
        }

        return sbomFiles;
    }

    private HashSet<SbomFile> ConvertToSbomFiles(List<Spdx30Entities.File> files, List<Element> spdx30Elements, List<Spdx30Entities.Relationship> relationships)
    {
        var sbomFiles = new HashSet<SbomFile>();

        foreach (var file in files)
        {
            sbomFiles.Add(file.ToSbomFile(spdx30Elements, relationships));
        }

        return sbomFiles;
    }

    private HashSet<SbomPackage> ConvertToSbomPackages(List<SPDXPackage> packages)
    {
        var sbomPackages = new HashSet<SbomPackage>();

        foreach (var package in packages)
        {
            sbomPackages.Add(package.ToSbomPackage());
        }

        return sbomPackages;
    }

    private HashSet<SbomPackage> ConvertToSbomPackages(List<Package> packages, List<Element> spdx30Elements, List<Spdx30Entities.Relationship> relationships)
    {
        var sbomPackages = new HashSet<SbomPackage>();

        foreach (var package in packages)
        {
            sbomPackages.Add(package.ToSbomPackage(spdx30Elements, relationships));
        }

        return sbomPackages;
    }

    private HashSet<SbomRelationship> ConvertToRelationships(List<SPDXRelationship> relationships)
    {
        var sbomRelationships = new HashSet<SbomRelationship>();

        foreach (var relationship in relationships)
        {
            sbomRelationships.Add(relationship.ToSbomRelationship());
        }

        return sbomRelationships;
    }

    private HashSet<SbomRelationship> ConvertToRelationships(List<Spdx30Entities.Relationship> relationships)
    {
        var sbomRelationships = new HashSet<SbomRelationship>();

        foreach (var relationship in relationships)
        {
            sbomRelationships.UnionWith(relationship.ToSbomRelationship());
        }

        return sbomRelationships;
    }

    private HashSet<SbomReference> ConvertToSbomReferences(List<SpdxExternalDocumentReference> externalDocRefs)
    {
        var sbomReferences = new HashSet<SbomReference>();

        foreach (var externalDocRef in externalDocRefs)
        {
            sbomReferences.Add(externalDocRef.ToSbomReference());
        }

        return sbomReferences;
    }

    private HashSet<SbomReference> ConvertToSbomReferences(List<ExternalMap> externalDocRefs)
    {
        var sbomReferences = new HashSet<SbomReference>();

        foreach (var externalDocRef in externalDocRefs)
        {
            sbomReferences.Add(externalDocRef.ToSbomReference());
        }

        return sbomReferences;
    }

    private JsonElement ReadJsonFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"The file at path {filePath} does not exist.");
        }

        var jsonContent = File.ReadAllText(filePath);
        return JsonDocument.Parse(jsonContent).RootElement;
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

    /// <summary>
    /// Get the SPDX 3.0 relationships that are not related to license information.
    /// </summary>
    /// <param name="elements"></param>
    /// <returns></returns>
    private List<Spdx30Entities.Relationship> GetSpdx30Relationships(List<Element> elements)
    {
        var relationships = elements.OfType<Spdx30Entities.Relationship>().ToList();
        return relationships
            .Where(element => element.RelationshipType != Spdx30Entities.Enums.RelationshipType.HAS_CONCLUDED_LICENSE &&
                              element.RelationshipType != Spdx30Entities.Enums.RelationshipType.HAS_DECLARED_LICENSE)
            .ToList();
    }
}
