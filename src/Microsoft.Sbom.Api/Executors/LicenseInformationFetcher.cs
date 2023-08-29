﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Newtonsoft.Json.Linq;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;
public class LicenseInformationFetcher : ILicenseInformationFetcher
{
    private readonly ILogger log;
    private readonly ConcurrentDictionary<string, string> licenseDictionary = new ConcurrentDictionary<string, string>();
    private readonly LicenseInformationService licenseInformationService;

    public LicenseInformationFetcher(ILogger log, LicenseInformationService licenseInformationService)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.licenseInformationService = licenseInformationService ?? throw new ArgumentNullException(nameof(licenseInformationService));
    }

    public List<string> ConvertComponentsToListForApi(IEnumerable<ScannedComponent> scannedComponents)
    {
        List<string> listOfComponentsForApi = new List<string>();

        foreach (var scannedComponent in scannedComponents)
        {
            string[] parts = scannedComponent.Component.Id.Split(' ');
            string componentVersion = scannedComponent.Component.PackageUrl?.Version;
            string componentType = scannedComponent.Component.PackageUrl?.Type.ToLower();

            if (parts.Length > 2)
            {
                var clearlyDefinedNamespace = "-";
                var componentName = scannedComponent.Component.PackageUrl?.Name;

                // If the clearlyDefinedName contains a / then split it and use the first part as the clearlyDefinedNamespace and the second part as the clearlyDefinedName
                if (componentName.Contains("/"))
                {
                    string[] clearlyDefinedNameParts = componentName.Split('/');
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

                    default:
                        log.Warning($"The component type {componentType} is not supported by ClearlyDefined.");
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
        Dictionary<string, string> extractedLicenses = new Dictionary<string, string>();

        try
        {
            JObject responseObject = JObject.Parse(httpResponseContent); // Parse the JSON string

            foreach (JToken packageInfoToken in responseObject.Values())
            {
                JObject packageInfo = packageInfoToken.ToObject<JObject>();
                JObject coordinates = packageInfo.Value<JObject>("coordinates");
                string packageNamespace = coordinates.Value<string>("namespace");
                string packageName = coordinates.Value<string>("name");
                string packageVersion = coordinates.Value<string>("revision");
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

                    extractedLicenses.TryAdd($"{packageName}@{packageVersion}", declaredLicense);
                }
            }
        }
        catch
        {
            log.Error("Encountered error while attempting to parse response. License information may not be fully recorded.");
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
        string value = string.Empty;

        if (licenseDictionary.ContainsKey(key))
        {
            licenseDictionary.TryGetValue(key, out value);
        }

        return value;
    }
}