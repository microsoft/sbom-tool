// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.Sbom.Api.Config.Extensions;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions;
using Constants = Microsoft.Sbom.Api.Utils.Constants;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Abstract class that runs component detection tool in the given folder.
/// </summary>
public abstract class ComponentDetectionBaseWalker
{
    private readonly ILogger log;
    private readonly ComponentDetectorCachedExecutor componentDetector;
    private readonly IConfiguration configuration;
    private readonly ISbomConfigProvider sbomConfigs;
    private readonly IFileSystemUtils fileSystemUtils;
    private readonly ILicenseInformationFetcher licenseInformationFetcher;
    private readonly RuntimeConfiguration? runtimeConfiguration;
    private readonly IPackageDetailsFactory packageDetailsFactory;

    public ConcurrentDictionary<string, string> LicenseDictionary = new ConcurrentDictionary<string, string>();
    private bool licenseInformationRetrieved = false;

    private ComponentDetectionCliArgumentBuilder cliArgumentBuilder;

    public ComponentDetectionBaseWalker(
        ILogger log,
        ComponentDetectorCachedExecutor componentDetector,
        IConfiguration configuration,
        ISbomConfigProvider sbomConfigs,
        IFileSystemUtils fileSystemUtils,
        IPackageDetailsFactory packageDetailsFactory,
        ILicenseInformationFetcher licenseInformationFetcher,
        RuntimeConfiguration? runtimeConfiguration)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.componentDetector = componentDetector ?? throw new ArgumentNullException(nameof(componentDetector));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.packageDetailsFactory = packageDetailsFactory ?? throw new ArgumentNullException(nameof(packageDetailsFactory));
        this.licenseInformationFetcher = licenseInformationFetcher ?? throw new ArgumentNullException(nameof(licenseInformationFetcher));
        this.runtimeConfiguration = runtimeConfiguration;
    }

    public (ChannelReader<ScannedComponent> output, ChannelReader<ComponentDetectorException> error) GetComponents(string buildComponentDirPath)
    {
        if (fileSystemUtils.FileExists(buildComponentDirPath))
        {
            log.Debug($"Scanning for packages under the root path {buildComponentDirPath}.");
        }

        // If the buildComponentDirPath is null or empty, make sure we have a ManifestDirPath and create a new temp directory with a random name.
        if (!fileSystemUtils.DirectoryExists(configuration.BuildComponentPath?.Value) && fileSystemUtils.DirectoryExists(configuration.ManifestDirPath?.Value))
        {
            buildComponentDirPath = fileSystemUtils.GetSbomToolTempPath();
            Directory.CreateDirectory(buildComponentDirPath);
        }

        cliArgumentBuilder = new ComponentDetectionCliArgumentBuilder();

        // Enable SPDX22 and ConanLock detector which is disabled by default.
        cliArgumentBuilder.AddDetectorArg("SPDX22SBOM", "EnableIfDefaultOff");
        cliArgumentBuilder.AddDetectorArg("ConanLock", "EnableIfDefaultOff");

        // Iterate over all supported SPDX manifests and apply the necessary logic
        foreach (var supportedSpdxManifest in Constants.SupportedSpdxManifests)
        {
            if (sbomConfigs.TryGet(supportedSpdxManifest, out var spdxSbomConfig))
            {
                var directory = Path.GetDirectoryName(spdxSbomConfig.ManifestJsonFilePath);
                directory = fileSystemUtils.GetFullPath(directory);
                if (!string.IsNullOrEmpty(directory))
                {
                    cliArgumentBuilder.AddArg("DirectoryExclusionList", directory);
                }
            }
        }

        var output = Channel.CreateUnbounded<ScannedComponent>();
        var errors = Channel.CreateUnbounded<ComponentDetectorException>();

        if (string.IsNullOrEmpty(buildComponentDirPath))
        {
            output.Writer.Complete();
            errors.Writer.Complete();
            return (output, errors);
        }

        async Task Scan(string path)
        {
            IDictionary<(string Name, string Version), PackageDetails.PackageDetails> packageDetailsDictionary = new ConcurrentDictionary<(string, string), PackageDetails.PackageDetails>();

            cliArgumentBuilder.SourceDirectory(buildComponentDirPath);

            var cmdLineParams = configuration.ToComponentDetectorCommandLineParams(cliArgumentBuilder);

            var scanSettings = cliArgumentBuilder.BuildScanSettingsFromParsedArgs(cmdLineParams);
            if (runtimeConfiguration != null)
            {
                scanSettings.NoSummary = runtimeConfiguration.NoComponentGovernanceSummary;
            }

            var scanResult = await componentDetector.ScanAsync(scanSettings);

            if (scanResult.ResultCode != ProcessingResultCode.Success)
            {
                await errors.Writer.WriteAsync(new ComponentDetectorException($"Component detector failed. Result: {scanResult.ResultCode}."));
                return;
            }

            var uniqueComponents = FilterScannedComponents(scanResult);

            if (configuration.EnablePackageMetadataParsing?.Value == true)
            {
                if (uniqueComponents.Any())
                {
                    packageDetailsDictionary = packageDetailsFactory.GetPackageDetailsDictionary(uniqueComponents);
                }
            }

            // Check if the configuration is set to fetch license information.
            if (configuration.FetchLicenseInformation?.Value == true)
            {
                var listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(uniqueComponents);

                // Check that an API call hasn't already been made. During the first execution of this class this list is empty (because we are detecting the files section of the SBOM). During the second execution we have all the components in the project. There are subsequent executions but not important in this scenario.
                if (!licenseInformationRetrieved && listOfComponentsForApi?.Count > 0)
                {
                    licenseInformationRetrieved = true;

                    List<string> apiResponses;

                    apiResponses = await licenseInformationFetcher.FetchLicenseInformationAsync(listOfComponentsForApi, configuration.LicenseInformationTimeoutInSeconds.Value);

                    foreach (var response in apiResponses)
                    {
                        var licenseInfo = licenseInformationFetcher.ConvertClearlyDefinedApiResponseToList(response);

                        if (licenseInfo != null)
                        {
                            licenseInformationFetcher.AppendLicensesToDictionary(licenseInfo);
                        }
                    }

                    LicenseDictionary = licenseInformationFetcher.GetLicenseDictionary();

                    log.Information($"Found license information for {LicenseDictionary.Count} out of {uniqueComponents.Count()} unique components.");
                }
            }

            // Converts every ScannedComponent into an ExtendedScannedComponent and attempts to add license information before writing to the channel.
            foreach (var scannedComponent in uniqueComponents)
            {
                var componentName = scannedComponent.Component.PackageUrl?.Name;
                var componentVersion = scannedComponent.Component.PackageUrl?.Version;

                ExtendedScannedComponent extendedComponent;

                if (scannedComponent is ExtendedScannedComponent existingExtendedScannedComponent)
                {
                    extendedComponent = existingExtendedScannedComponent;
                }
                else
                {
                    // Use copy constructor to pass over all the properties to the ExtendedScannedComponent.
                    extendedComponent = new ExtendedScannedComponent(scannedComponent);
                }

                if (LicenseDictionary != null && LicenseDictionary.ContainsKey($"{componentName}@{componentVersion}"))
                {
                    extendedComponent.LicenseConcluded = LicenseDictionary[$"{componentName}@{componentVersion}"];
                }

                if (packageDetailsDictionary != null && packageDetailsDictionary.ContainsKey((componentName, componentVersion)))
                {
                    extendedComponent.Supplier = string.IsNullOrEmpty(packageDetailsDictionary[(componentName, componentVersion)].Supplier) ? null : packageDetailsDictionary[(componentName, componentVersion)].Supplier;
                    extendedComponent.LicenseDeclared = string.IsNullOrEmpty(packageDetailsDictionary[(componentName, componentVersion)].License) ? null : packageDetailsDictionary[(componentName, componentVersion)].License;
                }

                await output.Writer.WriteAsync(extendedComponent);
            }
        }

        Task.Run(async () =>
        {
            try
            {
                await Scan(buildComponentDirPath);
            }
            catch (Exception e)
            {
                log.Error($"Unknown error while running CD scan: {e}");
                await errors.Writer.WriteAsync(new ComponentDetectorException("Unknown exception", e));
                return;
            }
            finally
            {
                output.Writer.Complete();
                errors.Writer.Complete();
            }
        });

        return (output, errors);
    }

    protected abstract IEnumerable<ScannedComponent> FilterScannedComponents(ScanResult result);
}
