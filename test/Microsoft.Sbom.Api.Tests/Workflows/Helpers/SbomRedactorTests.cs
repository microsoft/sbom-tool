// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Tests.Workflows.Helpers;

[TestClass]
public class SbomRedactorTests
{
    private Mock<IValidatedSBOM> mockValidatedSbom;

    private SbomRedactor testSubject;

    [TestInitialize]
    public void Init()
    {
        mockValidatedSbom = new Mock<IValidatedSBOM>();
        testSubject = new SbomRedactor();
    }

    [TestMethod]
    public async Task SbomRedactor_RemovesFilesSection()
    {
        var mockSbom = new FormatEnforcedSPDX2
        {
            Files = new List<SPDXFile>
            {
                new SPDXFile()
            }
        };
        mockValidatedSbom.Setup(x => x.GetRawSPDXDocument()).ReturnsAsync(mockSbom);
        await testSubject.RedactSBOMAsync(mockValidatedSbom.Object);
        Assert.IsNull(mockSbom.Files);
    }

    [TestMethod]
    public async Task SbomRedactor_RemovesPackageFileRefs()
    {
        var mockSbom = new FormatEnforcedSPDX2
        {
            Packages = new List<SPDXPackage>
            {
                new SPDXPackage()
                {
                    SpdxId = "package-1",
                    HasFiles = new List<string>
                    {
                        "file-1",
                        "file-2",
                    }
                },
                new SPDXPackage()
                {
                    SpdxId = "package-2",
                    SourceInfo = "source-info"
                },
                new SPDXPackage()
                {
                    SpdxId = "package-3",
                }
            }
        };
        mockValidatedSbom.Setup(x => x.GetRawSPDXDocument()).ReturnsAsync(mockSbom);
        await testSubject.RedactSBOMAsync(mockValidatedSbom.Object);
        Assert.AreEqual(mockSbom.Packages.Count(), 3);
        foreach (var package in mockSbom.Packages)
        {
            Assert.IsNull(package.HasFiles);
            Assert.IsNull(package.SourceInfo);
            Assert.IsNotNull(package.SpdxId);
        }
    }

    [TestMethod]
    public async Task SbomRedactor_RemovesRelationshipsWithFileRefs()
    {
        var unredactedRelationship = new SPDXRelationship()
        {
            SourceElementId = "source",
            TargetElementId = "target",
            RelationshipType = "relationship-3",
        };
        var mockSbom = new FormatEnforcedSPDX2
        {
            Relationships = new List<SPDXRelationship>
            {
                new SPDXRelationship()
                {
                    SourceElementId = "SPDXRef-File-1",
                    TargetElementId = "target",
                    RelationshipType = "relationship-1",
                },
                new SPDXRelationship()
                {
                    SourceElementId = "source",
                    TargetElementId = "SPDXRef-File-2",
                    RelationshipType = "relationship-2",
                },
                unredactedRelationship
            }
        };
        mockValidatedSbom.Setup(x => x.GetRawSPDXDocument()).ReturnsAsync(mockSbom);
        await testSubject.RedactSBOMAsync(mockValidatedSbom.Object);
        Assert.AreEqual(mockSbom.Relationships.Count(), 1);
        Assert.AreEqual(mockSbom.Relationships.First(), unredactedRelationship);
    }

    [TestMethod]
    public async Task SbomRedactor_UpdatesDocNamespaceForMsftSboms()
    {
        var docNamespace = "microsoft/test/namespace/fakeguid";
        var mockSbom = new FormatEnforcedSPDX2
        {
            DocumentNamespace = docNamespace
        };
        mockValidatedSbom.Setup(x => x.GetRawSPDXDocument()).ReturnsAsync(mockSbom);
        await testSubject.RedactSBOMAsync(mockValidatedSbom.Object);
        Assert.IsTrue(mockSbom.DocumentNamespace.Contains("microsoft/test/namespace/"));
        Assert.IsFalse(mockSbom.DocumentNamespace.Contains("fakeguid"));
    }

    [TestMethod]
    public async Task SbomRedactor_DoesNotEditDocNamespaceForNonMsftSboms()
    {
        var docNamespace = "test-namespace";
        var mockSbom = new FormatEnforcedSPDX2
        {
            DocumentNamespace = docNamespace
        };
        mockValidatedSbom.Setup(x => x.GetRawSPDXDocument()).ReturnsAsync(mockSbom);
        await testSubject.RedactSBOMAsync(mockValidatedSbom.Object);
        Assert.AreEqual(mockSbom.DocumentNamespace, docNamespace);
    }
}
