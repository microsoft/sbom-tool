// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Config.Extensions;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;
using Serilog.Events;
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

    public ConcurrentDictionary<string, string> LicenseDictionary = new ConcurrentDictionary<string, string>();
    private bool hasRun = false;

    private ComponentDetectionCliArgumentBuilder cliArgumentBuilder;

    public ComponentDetectionBaseWalker(
        ILogger log,
        ComponentDetectorCachedExecutor componentDetector,
        IConfiguration configuration,
        ISbomConfigProvider sbomConfigs,
        IFileSystemUtils fileSystemUtils,
        ILicenseInformationFetcher licenseInformationFetcher)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.componentDetector = componentDetector ?? throw new ArgumentNullException(nameof(componentDetector));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.licenseInformationFetcher = licenseInformationFetcher ?? throw new ArgumentNullException(nameof(licenseInformationFetcher));
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

        var verbosity = configuration.Verbosity.Value switch
        {
            LogEventLevel.Verbose => VerbosityMode.Verbose,
            _ => VerbosityMode.Normal,
        };

        cliArgumentBuilder = new ComponentDetectionCliArgumentBuilder().Scan().Verbosity(verbosity);

        // Enable SPDX22 detector which is disabled by default.
        cliArgumentBuilder.AddDetectorArg("SPDX22SBOM", "EnableIfDefaultOff");

        if (sbomConfigs.TryGet(Constants.SPDX22ManifestInfo, out ISbomConfig spdxSbomConfig))
        {
            var directory = Path.GetDirectoryName(spdxSbomConfig.ManifestJsonFilePath);
            if (!string.IsNullOrEmpty(directory))
            {
                cliArgumentBuilder.AddArg("DirectoryExclusionList", directory);
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
            cliArgumentBuilder.SourceDirectory(buildComponentDirPath);
            var cmdLineParams = configuration.ToComponentDetectorCommandLineParams(cliArgumentBuilder);

            var scanResult = await componentDetector.ScanAsync(cmdLineParams);

            if (scanResult.ResultCode != ProcessingResultCode.Success)
            {
                await errors.Writer.WriteAsync(new ComponentDetectorException($"Component detector failed. Result: {scanResult.ResultCode}."));
                return;
            }

            var uniqueComponents = FilterScannedComponents(scanResult);

            List<string> listOfComponentsForApi = licenseInformationFetcher.ConvertComponentsToListForApi(uniqueComponents);

            // Check that an API call hasn't already been made. During the first execution of this class this list is empty (because we are detecting the files section of the SBOM). During the second execution we have all the components in the project. There are subsequent executions but not important in this scenario.
            if (!hasRun && listOfComponentsForApi?.Count > 0)
            {
                hasRun = true;

                List<HttpResponseMessage> apiResponses = await licenseInformationFetcher.FetchLicenseInformationAsync(listOfComponentsForApi);

                foreach (HttpResponseMessage response in apiResponses)
                {
                    Dictionary<string, string> licenseInfo = await licenseInformationFetcher.ConvertClearlyDefinedApiResponseToList(response);

                    if (licenseInfo != null)
                    {
                          licenseInformationFetcher.AppendLicensesToDictionary(licenseInfo);
                    }
                }
            }

            LicenseDictionary = licenseInformationFetcher.GetLicenseDictionary();

            // This loop converts every ScannedComponent into an ExtendedScannedComponent and adds the license information to it. This was done because directly casting a ScannedComponent to an ExtendedScannedComponent does not work.
            foreach (ScannedComponent scannedComponent in uniqueComponents)
            {
                string componentName = scannedComponent.Component.PackageUrl?.Name;
                string componentVersion = scannedComponent.Component.PackageUrl?.Version;

                ScannedComponentWithLicense extendedComponent;

                if (scannedComponent is ScannedComponentWithLicense existingExtendedComponent)
                {
                    extendedComponent = existingExtendedComponent;
                }
                else
                {
                    // Use copy constructor to pass over all the properties to the ScanndedComponentWithLicense.
                    extendedComponent = new ScannedComponentWithLicense(scannedComponent);
                }

                if (LicenseDictionary != null && LicenseDictionary.ContainsKey($"{componentName}@{componentVersion}"))
                {
                    extendedComponent.License = LicenseDictionary[$"{componentName}@{componentVersion}"];
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