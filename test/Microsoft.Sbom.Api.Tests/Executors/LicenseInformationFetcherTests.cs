// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.Tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class LicenseInformationFetcherTests
{
    private readonly Mock<ILogger<LicenseInformationFetcher>> mockLogger = new Mock<ILogger<LicenseInformationFetcher>>();
    private readonly Mock<IRecorder> mockRecorder = new Mock<IRecorder>();
    private readonly Mock<ILicenseInformationService> mockLicenseInformationService = new Mock<ILicenseInformationService>();

    [TestMethod]
    public void ConvertComponentsToListForApi_Npm()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var scannedComponents = new List<ScannedComponent>
        {
            new ScannedComponent
            {
               Component = new NpmComponent("npmpackage", "1.0.0") { Author = null }
            },

            new ScannedComponent
            {
               Component = new NpmComponent("@npmpackageNamespace/testpackage", "1.0.0") { Author = null }
            },
        };

        var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("npm/npmjs/-/npmpackage/1.0.0", listOfComponentsForApi[0]);
        Assert.AreEqual("npm/npmjs/@npmpackagenamespace/testpackage/1.0.0", listOfComponentsForApi[1]);
    }

    [TestMethod]
    public void ConvertComponentToListForApi_NuGet()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var scannedComponents = new List<ScannedComponent>
        {
            new ScannedComponent
            {
               Component = new NuGetComponent("nugetpackage", "1.0.0")
            },

            new ScannedComponent
            {
               Component = new NuGetComponent("@nugetpackage/testpackage", "1.0.0")
            },
        };

        var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("nuget/nuget/-/nugetpackage/1.0.0", listOfComponentsForApi[0]);
        Assert.AreEqual("nuget/nuget/@nugetpackage/testpackage/1.0.0", listOfComponentsForApi[1]);
    }

    [TestMethod]
    public void ConvertComponentToListForApi_Pypi()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var scannedComponents = new List<ScannedComponent>
        {
            new ScannedComponent
            {
               Component = new PipComponent("pippackage", "1.0.0")
            }
        };

        var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("pypi/pypi/-/pippackage/1.0.0", listOfComponentsForApi[0]);
    }

    [TestMethod]
    public void ConvertComponentToListForApi_Gem()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var scannedComponents = new List<ScannedComponent>
        {
            new ScannedComponent
            {
               Component = new RubyGemsComponent("gempackage", "1.0.0")
            }
        };

        var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("gem/rubygems/-/gempackage/1.0.0", listOfComponentsForApi[0]);
    }

    [TestMethod]
    public void ConvertComponentToListForApi_Pod()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var scannedComponents = new List<ScannedComponent>
        {
            new ScannedComponent
            {
               Component = new PodComponent("podpackage", "1.0.0")
            }
        };

        var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("pod/cocoapods/-/podpackage/1.0.0", listOfComponentsForApi[0]);
    }

    [TestMethod]
    public void ConvertComponentToListForApi_Crate()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var scannedComponents = new List<ScannedComponent>
        {
            new ScannedComponent
            {
               Component = new CargoComponent("cratepackage", "1.0.0")
            }
        };

        var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("crate/cratesio/-/cratepackage/1.0.0", listOfComponentsForApi[0]);
    }

    [TestMethod]
    public void ConvertClearlyDefinedApiResponseToList_GoodResponse()
    {
        var expectedKey = "json5@2.2.3";
        var expectedValue = "MIT";
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var licensesDictionary = licenseInformationFetcher.ConvertClearlyDefinedApiResponseToList(HttpRequestUtils.GoodClearlyDefinedAPIResponse);

        CollectionAssert.Contains(licensesDictionary, new KeyValuePair<string, string>(expectedKey, expectedValue));
    }

    [TestMethod]
    public void ConvertClearlyDefinedApiResponseToList_BadResponse()
    {
        var licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockRecorder.Object, mockLicenseInformationService.Object);

        var licensesDictionary = licenseInformationFetcher.ConvertClearlyDefinedApiResponseToList(HttpRequestUtils.BadClearlyDefinedAPIResponse);

        Assert.AreEqual(0, licensesDictionary.Count);
    }
}
