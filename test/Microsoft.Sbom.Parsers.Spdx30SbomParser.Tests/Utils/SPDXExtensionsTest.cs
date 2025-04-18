// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Sbom.Common.Spdx30Entities;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Extensions.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Relationship = Microsoft.Sbom.Common.Spdx30Entities.Relationship;
using RelationshipType = Microsoft.Sbom.Common.Spdx30Entities.Enums.RelationshipType;

namespace Microsoft.Sbom.Utils;

[TestClass]
public class SPDXExtensionsTest
{
    private const string PackageSpdxIdWithMissingPackageId = "SPDXRef-Package-D99F4826E74FCF3A40C17AF7F82ED84E673D7D70975A6337C30F81C71E0C2BAC";
    private const string PackageSpdxIdWithPackageId = "SPDXRef-Package-D59091CB205934C58034F3FB2290A10F3DC6AFDA895B099066F9D40245A239C2";
    private const string PackageSpdxIdWithVersionAndMissingPackageId = "SPDXRef-Package-76A4881BB39276EA67CA840875A0EDFFE7562057AD19998491518B222D278E87";
    private const string ExternalReferenceSpdxId = "DocumentRef-externalRefName-sha1Value";
    private const string FileSpdxId = "SPDXRef-File-filePath-sha1Value";
    private const string ElementSpdxId = "SPDXRef-Element-82A3537FF0DBCE7EEC35D69EDC3A189EE6F17D82F353A553F9AA96CB0BE3CE89";

    private InternalSbomFileInfo fileInfo = null;
    private SbomPackage packageInfo = null;

    private File spdxFile = null;
    private Package spdxPackage = null;
    private ExternalMap externalMap = null;
    private IEnumerable<Checksum> checksums = new List<Checksum>
    {
        new Checksum
        {
            Algorithm = AlgorithmName.SHA1,
            ChecksumValue = "sha1Value",
        },
        new Checksum
        {
            Algorithm = AlgorithmName.SHA256,
            ChecksumValue = "sha256Value",
        }
    };

    private IEnumerable<Checksum> checksumsWithoutSHA1 = new List<Checksum>
    {
        new Checksum
        {
            Algorithm = AlgorithmName.SHA256,
            ChecksumValue = "sha256Value",
        }
    };

    [TestInitialize]
    public void Setup()
    {
        spdxPackage = new Package
        {
            Name = "packageName",
            PackageVersion = "1.0.0"
        };

        packageInfo = new SbomPackage
        {
            Id = "packageId",
            Type = "npm",
            PackageName = "packageName",
            PackageVersion = "1.0.0"
        };

        externalMap = new ExternalMap();

        fileInfo = new InternalSbomFileInfo()
        {
            Path = "filePath",
            Checksum = checksums
        };

        spdxFile = new File();
    }

    [TestMethod]
    public void AddSpdxIdToPackage_PackageInfoIsNull_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(() => spdxPackage.AddSpdxId(null));
    }

    [TestMethod]
    public void AddSpdxIdToPackage_PackageInfoWithIdAndVersion_Success()
    {
        spdxPackage.AddSpdxId(packageInfo);
        Assert.AreEqual(PackageSpdxIdWithPackageId, spdxPackage.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToPackage_PackageInfoWithIdAndMissingVersion_Success()
    {
        packageInfo.PackageVersion = null;
        spdxPackage.AddSpdxId(packageInfo);

        Assert.AreEqual(PackageSpdxIdWithPackageId, spdxPackage.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToPackage_PackageInfoMissingIdAndVersion_Success()
    {
        packageInfo.Id = null;
        packageInfo.PackageVersion = null;
        spdxPackage.AddSpdxId(packageInfo);
        Assert.AreEqual(PackageSpdxIdWithMissingPackageId, spdxPackage.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToPackage_PackageInfoWithVersionAndMissingId_Success()
    {
        packageInfo.Id = null;
        spdxPackage.AddSpdxId(packageInfo);
        Assert.AreEqual(PackageSpdxIdWithVersionAndMissingPackageId, spdxPackage.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToExternalReference_NullName_Throws()
    {
        Assert.ThrowsException<ArgumentException>(() => externalMap.AddExternalSpdxId(null, checksums));
    }

    [TestMethod]
    public void AddSpdxIdToExternalReference_NullChecksum_Throws()
    {
        Assert.ThrowsException<ArgumentNullException>(() => externalMap.AddExternalSpdxId("externalMap1", null));
    }

    [TestMethod]
    public void AddSpdxIdToExternalReference_ChecksumMissingSHA1Value_Throws()
    {
        Assert.ThrowsException<MissingHashValueException>(() => externalMap.AddExternalSpdxId("externalRefName", checksumsWithoutSHA1));
    }

    [TestMethod]
    public void AddSpdxIdToExternalReference_Succeeds()
    {
        externalMap.AddExternalSpdxId("externalRefName", checksums);
        Assert.AreEqual(ExternalReferenceSpdxId, externalMap.ExternalSpdxId);
        Assert.AreEqual(ExternalReferenceSpdxId, externalMap.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToFile_NullPath_Throws()
    {
        fileInfo.Path = null;
        var exception = Assert.ThrowsException<ArgumentException>(() => spdxFile.AddSpdxId(fileInfo));
        Assert.IsTrue(exception.Message.Contains("Path"), $"Incorrect exception message thrown: {exception.Message}");
    }

    [TestMethod]
    public void AddSpdxIdToFile_NullChecksum_Throws()
    {
        fileInfo.Checksum = null;
        var exception = Assert.ThrowsException<MissingHashValueException>(() => spdxFile.AddSpdxId(fileInfo));
    }

    [TestMethod]
    public void AddSpdxIdToFile_ChecksumMissingSHA1Value_Throws()
    {
        fileInfo.Checksum = checksumsWithoutSHA1;
        var exception = Assert.ThrowsException<MissingHashValueException>(() => spdxFile.AddSpdxId(fileInfo));
    }

    [TestMethod]
    public void AddSpdxIdToFile_Succeeds()
    {
        spdxFile.AddSpdxId(fileInfo);
        Assert.AreEqual(FileSpdxId, spdxFile.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToElement_Succeeds()
    {
        var element = new Element
        {
            Name = "name"
        };

        element.AddSpdxId();
        Assert.AreEqual(ElementSpdxId, element.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToElement_DifferentNames_Succeeds()
    {
        var element = new Element
        {
            Name = "name"
        };

        var otherElement = new Element
        {
            Name = "otherName"
        };

        element.AddSpdxId();
        otherElement.AddSpdxId();
        Assert.AreNotEqual(element.SpdxId, otherElement.SpdxId);
    }

    [TestMethod]
    public void AddSpdxIdToRelationships_DifferentRelationshipType_HaveUniqueSpdxIds()
    {
        var relationship1 = new Relationship
        {
            From = "Source1",
            To = new List<string> { "Target1" },
            RelationshipType = RelationshipType.DEPENDS_ON
        };

        var relationship2 = new Relationship
        {
            From = "Source1",
            To = new List<string> { "Target1" },
            RelationshipType = RelationshipType.CONTAINS
        };

        relationship1.AddSpdxId();
        relationship2.AddSpdxId();

        Assert.AreNotEqual(relationship1.SpdxId, relationship2.SpdxId, "SPDX IDs for different relationship types should be unique.");
    }

    [TestMethod]
    public void AddSpdxIdToRelationships_DifferentSource_HaveUniqueSpdxIds()
    {
        var relationship1 = new Relationship
        {
            From = "Source1",
            To = new List<string> { "Target1" },
            RelationshipType = RelationshipType.DEPENDS_ON
        };

        var relationship2 = new Relationship
        {
            From = "Source2",
            To = new List<string> { "Target1" },
            RelationshipType = RelationshipType.DEPENDS_ON
        };

        relationship1.AddSpdxId();
        relationship2.AddSpdxId();

        Assert.AreNotEqual(relationship1.SpdxId, relationship2.SpdxId, "SPDX IDs for relationships with different sources should be unique.");
    }

    [TestMethod]
    public void AddSpdxIdToRelationships_SameSourceTargetAndType_HaveSameSpdxId()
    {
        var relationship1 = new Relationship
        {
            From = "Source1",
            To = new List<string> { "Target1" },
            RelationshipType = RelationshipType.DEPENDS_ON
        };

        var relationship2 = new Relationship
        {
            From = "Source1",
            To = new List<string> { "Target1" },
            RelationshipType = RelationshipType.DEPENDS_ON
        };

        relationship1.AddSpdxId();
        relationship2.AddSpdxId();

        Assert.AreEqual(relationship1.SpdxId, relationship2.SpdxId, "SPDX IDs for relationships with the same source, target, and type should be the same.");
    }
}
