// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
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
using Newtonsoft.Json.Linq;
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

    public readonly Dictionary<string, string> LicenseDictionary = new Dictionary<string, string>();
    private bool hasRun = false;

    private ComponentDetectionCliArgumentBuilder cliArgumentBuilder;

    public ComponentDetectionBaseWalker(
        ILogger log,
        ComponentDetectorCachedExecutor componentDetector,
        IConfiguration configuration,
        ISbomConfigProvider sbomConfigs,
        IFileSystemUtils fileSystemUtils)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.componentDetector = componentDetector ?? throw new ArgumentNullException(nameof(componentDetector));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.sbomConfigs = sbomConfigs ?? throw new ArgumentNullException(nameof(sbomConfigs));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
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

            var listOfLicenses = new List<string>();
            var clearlyDefinedType = string.Empty;
            var clearlyDefinedProvider = string.Empty;
            var clearlyDefinedNamespace = string.Empty;
            var clearlyDefinedName = string.Empty;
            var clearlyDefinedRevision = string.Empty;
            // var clearlyDefinedExpand = "-files";

            List<string> listOfComponentsForApi = new List<string>();

            // We have two for loops here so that when we break from the switch statement we are still within the outer loop where we await output.Writer.WriteAsync(component);
            foreach (var component in uniqueComponents)
            {
                foreach (var scannedComponent in uniqueComponents)
                {
                    string[] parts = scannedComponent.Component.Id.Split(' ');
                    string componentVersion = scannedComponent.Component.PackageUrl.Version;
                    string componentType = scannedComponent.Component.PackageUrl.Type.ToLower();

                    if (parts.Length > 2)
                    {
                        clearlyDefinedNamespace = "-";
                        clearlyDefinedName = parts[0];
                        clearlyDefinedType = parts[3];
                        clearlyDefinedProvider = parts[3];

                        // If the clearlyDefinedName contains a / then split it and use the first part as the clearlyDefinedNamespace and the second part as the clearlyDefinedName
                        if (clearlyDefinedName.Contains("/"))
                        {
                            string[] clearlyDefinedNameParts = clearlyDefinedName.Split('/');
                            clearlyDefinedNamespace = clearlyDefinedNameParts[0];
                            clearlyDefinedName = clearlyDefinedNameParts[1];
                        }

                        // Each componentType has it's own edge cases. So more work is needed before I can add more types.
                        switch (componentType)
                        {
                            case "npm":
                                listOfComponentsForApi.Add($"{componentType}/npmjs/{clearlyDefinedNamespace}/{clearlyDefinedName}/{componentVersion}");
                                break;
                            case "pypi":
                                listOfComponentsForApi.Add($"{componentType}/pypi/{clearlyDefinedNamespace}/{clearlyDefinedName}/{componentVersion}");
                                break;
                            case "maven":
                                listOfComponentsForApi.Add($"{componentType}/mavencentral/{clearlyDefinedNamespace}/{clearlyDefinedName}/{componentVersion}");
                                // listOfComponentsForApi.Add($"{clearlyDefinedType}/mavengoogle/{clearlyDefinedNamespace}/{clearlyDefinedName}/{clearlyDefinedRevision}");
                                break;
                            case "nuget":
                                listOfComponentsForApi.Add($"{componentType}/nuget/{clearlyDefinedNamespace}/{clearlyDefinedName}/{componentVersion}");
                                break;
                            case "pod":
                                listOfComponentsForApi.Add($"{componentType}/cocoapods/{clearlyDefinedNamespace}/{clearlyDefinedName}/{componentVersion}");
                                break;

                            default:
                                log.Information($"The component type {componentType} is not supported by ClearlyDefined.");
                                break;
                        }
                    }
                }

                // Check that an API call hasn't already been made. During the first execution of this class this list is empty (because we are detecting the files section of the SBOM). During the second execution we have all the components in the project. There are subsequent executions but not important in this scenario.
                if (!hasRun && listOfComponentsForApi.Count > 0)
                {
                    hasRun = true;
                    int batchSize = 350; // Set the batch size as needed

                    for (int i = 0; i < listOfComponentsForApi.Count; i += batchSize)
                    {
                        List<string> batch = listOfComponentsForApi.Skip(i).Take(batchSize).ToList();
                        string formattedData = "[" + string.Join(",", batch.Select(item => $"\"{item}\"")) + "]";

                        log.Information($"Retrieving license information for {batch.Count} components...");

                        using (HttpClient httpClient = new HttpClient())
                        {
                            string url = "https://api.clearlydefined.io/definitions";
                            var content = new StringContent(formattedData, Encoding.UTF8, "application/json");

                            // Set the headers individually
                            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                            httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                            // start timer
                            var watch = System.Diagnostics.Stopwatch.StartNew();

                            HttpResponseMessage response = await httpClient.PostAsync(url, content);

                            // stop timer
                            watch.Stop();

                            // Get the elapsed time as a TimeSpan value.
                            TimeSpan ts = watch.Elapsed;

                            // Format and display the TimeSpan value.
                            string elapsedTime = $"{ts.Hours:00}:{ts.Minutes:00}:{ts.Seconds:00}.{ts.Milliseconds / 10:00}.{ts.Milliseconds % 10:00}";

                            if (response.IsSuccessStatusCode)
                            {
                                string responseContent = await response.Content.ReadAsStringAsync();

                                log.Information($"Received response from {batch.Count} components in {elapsedTime}.");

                                JObject responseObject = JObject.Parse(responseContent); // Parse the JSON string

                                foreach (JToken packageInfoToken in responseObject.Values())
                                {
                                    JObject packageInfo = packageInfoToken.ToObject<JObject>();
                                    JObject coordinates = packageInfo.Value<JObject>("coordinates");
                                    string packageNamespace = coordinates.Value<string>("namespace");
                                    string packageName = coordinates.Value<string>("name");
                                    string declaredLicense = packageInfo
                                        .Value<JObject>("licensed")
                                        .Value<string>("declared");

                                    if (!string.IsNullOrEmpty(packageName) && !string.IsNullOrEmpty(declaredLicense))
                                    {
                                        // If a package has a namespace then we need to put it back in the appropriate format in order to find it in the dictionary when we write the JSON.
                                        if (!string.IsNullOrEmpty(packageNamespace))
                                        {
                                            packageName = $"{packageNamespace}/{packageName}";
                                        }

                                        LicenseDictionary[packageName] = declaredLicense;
                                    }
                                }

                                // Store the licenseDictionary in the global holder
                                foreach (var kvp in LicenseDictionary)
                                {
                                    GlobalLicenseDictionary.LicenseDictionary[kvp.Key] = kvp.Value;
                                }
                            }
                            else
                            {
                                log.Warning($"Batch request {(i / batchSize) + 1} failed. Status code: {response.StatusCode}");
                            }
                        }
                    }
                }

                await output.Writer.WriteAsync(component);
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