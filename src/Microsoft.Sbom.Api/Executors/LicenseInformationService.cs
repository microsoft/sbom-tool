// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;
public class LicenseInformationService
{
    private readonly ILogger log;

    public LicenseInformationService(ILogger log)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
    }

    public async Task<List<string>> FetchLicenseInformationFromAPI(List<string> listOfComponentsForApi)
    {
        int batchSize = 400;
        List<HttpResponseMessage> responses = new List<HttpResponseMessage>();
        List<string> responseContent = new List<string>();

        for (int i = 0; i < listOfComponentsForApi.Count; i += batchSize)
        {
            List<string> batch = listOfComponentsForApi.Skip(i).Take(batchSize).ToList();
            string formattedData = "[" + string.Join(",", batch.Select(item => $"\"{item}\"")) + "]";

            log.Information($"Retrieving license information for {batch.Count} components...");

            using (HttpClient httpClient = new HttpClient())
            {
                Uri uri = new Uri("https://api.clearlydefined.io/definitions");
                var content = new StringContent(formattedData, Encoding.UTF8, "application/json");

                // Set the headers individually
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                try
                {
                    // start timer
                    var watch = Stopwatch.StartNew();

                    responses.Add(await httpClient.PostAsync(uri, content));

                    // stop timer
                    watch.Stop();

                    // Get the elapsed time as a TimeSpan value.
                    TimeSpan ts = watch.Elapsed;

                    // Format and display the TimeSpan value.
                    string elapsedTime = $"{ts.Hours:00}:{ts.Minutes:00}:{ts.Seconds:00}.{ts.Milliseconds / 10:00}.{ts.Milliseconds % 10:00}";

                    log.Information($"Received response for {batch.Count} components in {elapsedTime}.");
                }
                catch (Exception e)
                {
                    log.Error($"Error encountered while fetching license information from API, resulting SBOM may have incomplete license information: {e.Message}");
                }
            }
        }

        foreach (HttpResponseMessage response in responses)
        {
            if (response.IsSuccessStatusCode)
            {
                responseContent.Add(await response.Content.ReadAsStringAsync());
            }
            else
            {
                log.Error($"Error encountered while fetching license information from API, resulting SBOM may have incomplete license information. Request returned status code: {response.StatusCode}");
            }
        }

        return responseContent;
    }
}