// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Newtonsoft.Json.Linq;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

public class LicenseInformationFetcher : ILicenseInformationFetcher
{
    private readonly ILogger log;
    private readonly IRecorder recorder;
    private readonly ILicenseInformationService licenseInformationService;
    private readonly ConcurrentDictionary<string, string> licenseDictionary = new ConcurrentDictionary<string, string>();

    public LicenseInformationFetcher(ILogger log, IRecorder recorder, ILicenseInformationService licenseInformationService)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.licenseInformationService = licenseInformationService ?? throw new ArgumentNullException(nameof(licenseInformationService));
    }

    public List<string> ConvertComponentsToListForApi(IEnumerable<ScannedComponent> scannedComponents)
    {
        var listOfComponentsForApi = new List<string>();

        foreach (var scannedComponent in scannedComponents)
        {
            var parts = scannedComponent.Component.Id.Split(' ');
            var componentVersion = scannedComponent.Component.PackageUrl?.Version;
            var componentType = scannedComponent.Component.PackageUrl?.Type.ToLower();

            if (parts.Length > 2)
            {
                var clearlyDefinedNamespace = "-";
                var componentName = scannedComponent.Component.PackageUrl?.Name;

                // If the clearlyDefinedName contains a / then split it and use the first part as the clearlyDefinedNamespace and the second part as the clearlyDefinedName
                if (!string.IsNullOrEmpty(componentName) && componentName.Contains('/'))
                {
                    var clearlyDefinedNameParts = componentName.Split('/');
                    clearlyDefinedNamespace = clearlyDefinedNameParts[0];
                    componentName = clearlyDefinedNameParts[1];
                }

                switch (componentType)
                {
                    case "npm":
                        listOfComponentsForApi.Add($"{componentType}/npmjs/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "nuget":
                        listOfComponentsForApi.Add($"{componentType}/nuget/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "gem":
                        listOfComponentsForApi.Add($"{componentType}/rubygems/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "pypi":
                        listOfComponentsForApi.Add($"{componentType}/pypi/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "cargo":
                        listOfComponentsForApi.Add($"crate/cratesio/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "cocoapods":
                        listOfComponentsForApi.Add($"pod/{componentType}/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;

                    default:
                        log.Debug($"License retrieval for component type {componentType} is not supported yet.");
                        break;
                }
            }
        }

        return listOfComponentsForApi;
    }

    public async Task<List<string>> FetchLicenseInformationAsync(List<string> listOfComponentsForApi)
    {
        return await licenseInformationService.FetchLicenseInformationFromAPI(listOfComponentsForApi);
    }

    // Will attempt to extract license information from a clearlyDefined batch API response. Will always return a dictionary which may be empty depending on the response.
    public Dictionary<string, string> ConvertClearlyDefinedApiResponseToList(string httpResponseContent)
    {
        var extractedLicenses = new Dictionary<string, string>();

        try
        {
            var responseObject = JObject.Parse(httpResponseContent);

            foreach (var packageInfoToken in responseObject.Values())
            {
                var packageInfo = packageInfoToken.ToObject<JObject>();
                var coordinates = packageInfo.Value<JObject>("coordinates");
                var packageNamespace = coordinates.Value<string>("namespace");
                var packageName = coordinates.Value<string>("name");
                var packageVersion = coordinates.Value<string>("revision");
                var declaredLicense = packageInfo
                    .Value<JObject>("licensed")
                    .Value<string>("declared");

                if (!string.IsNullOrEmpty(packageName) && !string.IsNullOrEmpty(declaredLicense))
                {
                    // If a package has a namespace then we need to put it back in the appropriate format in order to find it in the dictionary when we write the JSON.
                    if (!string.IsNullOrEmpty(packageNamespace))
                    {
                        packageName = $"{packageNamespace}/{packageName}";
                    }

                    extractedLicenses.TryAdd($"{packageName}@{packageVersion}", declaredLicense);
                }
            }

            // Filter out undefined licenses.
            foreach (var kvp in extractedLicenses.Where(kvp => kvp.Value.ToLower() == "noassertion" || kvp.Value.ToLower() == "unlicense" || kvp.Value.ToLower() == "other").ToList())
            {
                extractedLicenses.Remove(kvp.Key);
            }

            recorder.AddToTotalCountOfLicenses(extractedLicenses.Count);
        }
        catch
        {
            recorder.RecordAPIException(new ClearlyDefinedResponseParsingException("Encountered error while attempting to parse response. License information may not be fully recorded."));
            log.Warning("Encountered error while attempting to parse response. License information may not be fully recorded.");
            return extractedLicenses;
        }

        return extractedLicenses;
    }

    public ConcurrentDictionary<string, string> GetLicenseDictionary()
    {
        return licenseDictionary;
    }

    public void AppendLicensesToDictionary(Dictionary<string, string> partialLicenseDictionary)
    {
        foreach (var kvp in partialLicenseDictionary)
        {
            licenseDictionary.TryAdd(kvp.Key, kvp.Value);
        }
    }

    public string GetFromLicenseDictionary(string key)
    {
        var value = string.Empty;

        if (licenseDictionary.ContainsKey(key))
        {
            licenseDictionary.TryGetValue(key, out value);
        }

        return value;
    }
}
