using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Newtonsoft.Json.Linq;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;
public class LicenseInformationFetcher : ILicenseInformationFetcher
{
    private readonly ILogger log;
    private readonly ConcurrentDictionary<string, string> licenseDictionary = new ConcurrentDictionary<string, string>();

    public LicenseInformationFetcher(ILogger log)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public List<string> ConvertComponentsToListForApi(IEnumerable<ScannedComponent> scannedComponents)
    {
        // var clearlyDefinedExpand = "-files";

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

                // Each componentType has it's own edge cases. So more work is needed before I can add more types.
                switch (componentType)
                {
                    case "npm":
                        listOfComponentsForApi.Add($"{componentType}/npmjs/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "pypi":
                        listOfComponentsForApi.Add($"{componentType}/pypi/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "maven":
                        listOfComponentsForApi.Add($"{componentType}/mavencentral/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        // listOfComponentsForApi.Add($"{clearlyDefinedType}/mavengoogle/{clearlyDefinedNamespace}/{clearlyDefinedName}/{clearlyDefinedRevision}");
                        break;
                    case "nuget":
                        listOfComponentsForApi.Add($"{componentType}/nuget/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;
                    case "pod":
                        listOfComponentsForApi.Add($"{componentType}/cocoapods/{clearlyDefinedNamespace}/{componentName}/{componentVersion}");
                        break;

                    default:
                        log.Warning($"The component type {componentType} is not supported by ClearlyDefined.");
                        break;
                }
            }
        }

        return listOfComponentsForApi;
    }

    public async Task<List<HttpResponseMessage>> FetchLicenseInformationAsync(List<string> listOfComponentsForApi)
    {
        int batchSize = 400;
        List<HttpResponseMessage> responses = new List<HttpResponseMessage>();

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

                responses.Add(await httpClient.PostAsync(url, content));

                // stop timer
                watch.Stop();

                // Get the elapsed time as a TimeSpan value.
                TimeSpan ts = watch.Elapsed;

                // Format and display the TimeSpan value.
                string elapsedTime = $"{ts.Hours:00}:{ts.Minutes:00}:{ts.Seconds:00}.{ts.Milliseconds / 10:00}.{ts.Milliseconds % 10:00}";

                log.Information($"Retrieved license information for {batch.Count} components in {elapsedTime}.");
            }
        }

        return responses;
    }

    // Will attempt to extract license information from a clearlyDefined batch API response. Will always return a dictionary which may be empty depending on the response.
    public async Task<Dictionary<string, string>> ConvertClearlyDefinedApiResponseToList(HttpResponseMessage httpResponse)
    {
        Dictionary<string, string> extractedLicenses = new Dictionary<string, string>();

        if (httpResponse.IsSuccessStatusCode)
        {
            string responseContent = await httpResponse.Content.ReadAsStringAsync();

            JObject responseObject = JObject.Parse(responseContent); // Parse the JSON string

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
        else
        {
            log.Error($"Error while fetching license information from API: {httpResponse.IsSuccessStatusCode}");
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