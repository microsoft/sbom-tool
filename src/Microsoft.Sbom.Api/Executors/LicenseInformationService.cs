// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Output.Telemetry;
using Serilog;

namespace Microsoft.Sbom.Api.Executors;

public class LicenseInformationService : ILicenseInformationService
{
    private readonly ILogger log;
    private readonly IRecorder recorder;
    private readonly HttpClient httpClient;
    private const int ClientTimeoutSeconds = 30;

    public LicenseInformationService(ILogger log, IRecorder recorder, HttpClient httpClient)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    public async Task<List<string>> FetchLicenseInformationFromAPI(List<string> listOfComponentsForApi)
    {
        int batchSize = 500;
        List<HttpResponseMessage> responses = new List<HttpResponseMessage>();
        List<string> responseContent = new List<string>();

        Uri uri = new Uri("https://api.clearlydefined.io/definitions?expand=-files");

        httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        httpClient.Timeout = TimeSpan.FromSeconds(ClientTimeoutSeconds);

        for (int i = 0; i < listOfComponentsForApi.Count; i += batchSize)
        {
            List<string> batch = listOfComponentsForApi.Skip(i).Take(batchSize).ToList();
            string formattedData = JsonSerializer.Serialize(batch);

            log.Debug($"Retrieving license information for {batch.Count} components...");

            var content = new StringContent(formattedData, Encoding.UTF8, "application/json");
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                responses.Add(await httpClient.PostAsync(uri, content));
            }
            catch (Exception e)
            {
                log.Error($"Error encountered while fetching license information from API, resulting SBOM may have incomplete license information: {e.Message}");
                recorder.RecordAPIException(new ClearlyDefinedResponseNotSuccessfulException(e.Message));
            }

            stopwatch.Stop();

            log.Debug($"Retrieving license information for {batch.Count} components took {stopwatch.Elapsed.TotalSeconds} seconds");
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
                recorder.RecordAPIException(new ClearlyDefinedResponseNotSuccessfulException($"Request returned status code: {response.StatusCode}"));
            }
        }

        return responseContent;
    }
}
