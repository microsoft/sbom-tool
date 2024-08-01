// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.FormatValidator;

[TestClass]
public class FormatValidatorTests
{
    [TestMethod]
    public async Task FormatValidator_CanReadValidSbom()
    {
        using (var sbomStream = CreateStream(FormatValidatorTestStrings.JsonSuitableForRedaction))
        {
            var sbom = new ValidatedSBOM(sbomStream);
            var rawspdx = await sbom.GetRawSPDXDocument();
            var details = await sbom.GetValidationResults();

            Assert.AreEqual(FormatValidationStatus.Valid, details.Status);
            Assert.IsTrue(details.Errors.Count == 0);
            Assert.IsNotNull(rawspdx);
            Assert.AreEqual("SPDX-2.2", rawspdx.Version);
            Assert.AreEqual("CC0-1.0", rawspdx.DataLicense);
            Assert.AreEqual("sbom-tool 1.0.0", rawspdx.Name);
            Assert.AreEqual("https://microsoft.com/sbom-tool/test/sbom-tool/1.0.0/cuK7iCCPVEuSmgBfeFPc-g", rawspdx.DocumentNamespace);
            Assert.AreEqual(rawspdx.CreationInfo.Created, "2024-05-08T15:58:25Z");
            Assert.IsNotNull(rawspdx.CreationInfo.Creators);
            Assert.IsNotNull(rawspdx.DocumentDescribes);
        }
    }

    [DataTestMethod]
    [DataRow(FormatValidatorTestStrings.JsonMissingSpdxVersion, "spdxVersion")]
    [DataRow(FormatValidatorTestStrings.JsonMissingSpdxDataLicense, "dataLicense")]
    [DataRow(FormatValidatorTestStrings.JsonMissingDocumentNamespace, "documentNamespace")]
    [DataRow(FormatValidatorTestStrings.JsonMissingSpdxName, "name")]
    [DataRow(FormatValidatorTestStrings.JsonMissingSpdxPackages, "packages")]
    [DataRow(FormatValidatorTestStrings.JsonMissingSpdxRelationships, "relationships")]
    [DataRow(FormatValidatorTestStrings.JsonMissingSpdxCreationInfo, "creationInfo")]
    public async Task FormatValidator_FailsIfRequiredAttributeMissing(string json, string attribute)
    {
        using (var sbomStream = CreateStream(json))
        {
            var sbom = new ValidatedSBOM(sbomStream);
            var rawspdx = await sbom.GetRawSPDXDocument();
            var details = await sbom.GetValidationResults();

            Assert.AreEqual(FormatValidationStatus.NotValid, details.Status);
            Assert.IsTrue(details.Errors.Count > 0);

            // We want the error message to clearly signal the missing element.
            Assert.IsTrue(ErrorContains(details.Errors, attribute));
            Assert.IsTrue(ErrorContains(details.Errors, "missing required properties"));
        }
    }

    [TestMethod]
    public async Task FormatValidator_FailsForUnsupportedVersion()
    {
        // In the real world this is an unlikely scenario; SPDX v3 is so different from v2 that an attempt
        // to deserialize using a v2 model will fail. So this is more likely to catch some scenario where
        // the document was 2.x but the version was improperly serialized.
        using (var sbomStream = CreateStream(FormatValidatorTestStrings.JsonUnsupportedSpdxVersion))
        {
            var sbom = new ValidatedSBOM(sbomStream);
            var rawspdx = await sbom.GetRawSPDXDocument();
            var details = await sbom.GetValidationResults();

            Assert.AreEqual(FormatValidationStatus.NotValid, details.Status);
            Assert.IsTrue(details.Errors.Count > 0);

            // We want the error message to clearly signal the erroring element.
            Assert.IsTrue(ErrorContains(details.Errors, "SPDX-3.2 is not recognized"));
        }
    }

    [TestMethod]
    public async Task FormatValidator_FailsForMalformedJson()
    {
        using (var sbomStream = CreateStream(FormatValidatorTestStrings.MalformedJson))
        {
            var sbom = new ValidatedSBOM(sbomStream);
            var rawspdx = await sbom.GetRawSPDXDocument();
            var details = await sbom.GetValidationResults();

            Assert.AreEqual(FormatValidationStatus.NotValid, details.Status);
            Assert.IsTrue(details.Errors.Count > 0);

            // We want the error message to indicate that this is a Json parse error, and providing
            // context on where the error occurred is helpful too.
            Assert.IsTrue(ErrorContains(details.Errors, "is an invalid start of a value"));
            Assert.IsTrue(ErrorContains(details.Errors, "Path: $.externalDocumentRefs[0]"));
        }
    }

    [TestMethod]
    public async Task FormatValidator_CanDeserializeAllSpdx23Attributes()
    {
        using (var sbomStream = CreateStream(SpdxExemplars.JsonSpdx23Exemplar))
        {
            var sbom = new ValidatedSBOM(sbomStream);
            var rawspdx = await sbom.GetRawSPDXDocument();
            var details = await sbom.GetValidationResults();

            Assert.AreEqual(FormatValidationStatus.Valid, details.Status);
            Assert.AreEqual("SPDXRef-DOCUMENT", rawspdx.SPDXID);
            Assert.AreEqual("SPDX-2.3", rawspdx.Version);
            Assert.AreEqual("CC0-1.0", rawspdx.DataLicense);
            Assert.AreEqual(5, rawspdx.ExtractedLicensingInfos.ToList().Count);
            Assert.AreEqual(1, rawspdx.ExternalDocumentReferences.ToList().Count);
            Assert.AreEqual(3, rawspdx.Annotations.ToList().Count);
            Assert.AreEqual(1, rawspdx.Snippets.ToList().Count);
        }
    }

    [TestMethod]
    public void ValidationDetails_AggregateValidationStatus()
    {
        var details = new FormatValidationResults();
        details.AggregateValidationStatus(FormatValidationStatus.Valid);
        Assert.AreEqual(FormatValidationStatus.Valid, details.Status);

        details.AggregateValidationStatus(FormatValidationStatus.Valid);
        Assert.AreEqual(FormatValidationStatus.Valid, details.Status);

        details.AggregateValidationStatus(FormatValidationStatus.NotValid);
        Assert.AreEqual(FormatValidationStatus.NotValid, details.Status);

        // Once we detect any validation failure, the status should always stay NotValid.
        details.AggregateValidationStatus(FormatValidationStatus.Valid);
        Assert.AreEqual(FormatValidationStatus.NotValid, details.Status);
    }

    [TestMethod]
    public void SPDXVersionParsing_CanParseVersion()
    {
        var version = "SPDX-2.3";
        var versionMatched = SPDXVersionParser.VersionMatchesRequiredVersion(version, 2);
        Assert.IsTrue(versionMatched);

        version = "SPDX-2.2";
        versionMatched = SPDXVersionParser.VersionMatchesRequiredVersion(version, 2);
        Assert.IsTrue(versionMatched);

        version = "version 2.2";
        versionMatched = SPDXVersionParser.VersionMatchesRequiredVersion(version, 2);
        Assert.IsFalse(versionMatched);

        version = "SPDX-3.0";
        versionMatched = SPDXVersionParser.VersionMatchesRequiredVersion(version, 2);
        Assert.IsFalse(versionMatched);

        version = "frimplepants";
        versionMatched = SPDXVersionParser.VersionMatchesRequiredVersion(version, 2);
        Assert.IsFalse(versionMatched);
    }

    private Stream CreateStream(string json)
    {
        var utf8BOM = Encoding.UTF8.GetString(Encoding.UTF8.Preamble);
        var bytes = Encoding.UTF8.GetBytes(utf8BOM + json);
        return new MemoryStream(bytes);
    }

    private bool ErrorContains(List<string> errors, string message)
    {
        foreach (var error in errors)
        {
            if (error.Contains(message))
            {
                return true;
            }
        }

        return false;
    }
}
