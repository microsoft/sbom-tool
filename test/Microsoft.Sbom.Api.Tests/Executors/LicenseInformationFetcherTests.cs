// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class LicenseInformationFetcherTests
{
    private readonly Mock<ILogger> mockLogger = new Mock<ILogger>();
    private Mock<LicenseInformationService> mockLicenseInformationService;

    [TestInitialize]
    public void Setup()
    {
        mockLicenseInformationService = new Mock<LicenseInformationService>(mockLogger.Object);
    }

    [TestMethod]
    public void ConvertComponentsToListForApi_Npm()
    {
        LicenseInformationFetcher licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockLicenseInformationService.Object);

        List<ScannedComponent> scannedComponents = new List<ScannedComponent>
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

        List<string> listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("npm/npmjs/-/npmpackage/1.0.0", listOfComponentsForApi[0]);
        Assert.AreEqual("npm/npmjs/@npmpackagenamespace/testpackage/1.0.0", listOfComponentsForApi[1]);
    }

    [TestMethod]
    public void ConvertComponentToListForApi_NuGet()
    {
        LicenseInformationFetcher licenseInformationFetcher = new LicenseInformationFetcher(mockLogger.Object, mockLicenseInformationService.Object);

        List<ScannedComponent> scannedComponents = new List<ScannedComponent>
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

        List<string> listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(scannedComponents);

        Assert.AreEqual("nuget/nuget/-/nugetpackage/1.0.0", listOfComponentsForApi[0]);
        Assert.AreEqual("nuget/nuget/@nugetpackage/testpackage/1.0.0", listOfComponentsForApi[1]);
    }
}