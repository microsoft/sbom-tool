// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.Executors;

public interface ILicenseInformationFetcher
{
    /// <summary>
    /// Converts the list of scanned components to a list of strings that can be used to call the ClearlyDefined API.
    /// </summary>
    /// <param name="scannedComponents"> An IEnumerable of ScannedComponents given by the Component Detection libraries after a scan is completed.</param>
    public IList<string> ConvertComponentsToListForApi(IEnumerable<ScannedComponent> scannedComponents);

    /// <summary>
    /// Calls the ClearlyDefined API to get the license information for the list of components.
    /// </summary>
    /// <param name="listOfComponentsForApi"> A list of strings formatted into a list of strings that can be used to call the batch ClearlyDefined API.</param>
    /// <param name="timeoutInSeconds">Timeout in seconds to use when making web requests. Caller owns sanitizing this value</param>
    public Task<IList<string>> FetchLicenseInformationAsync(IList<string> listOfComponentsForApi, int timeoutInSeconds);

    /// <summary>
    /// Gets the dictionary of licenses that were fetched from the ClearlyDefined API.
    /// </summary>
    public ConcurrentDictionary<string, string> GetLicenseDictionary();

    /// <summary>
    /// Converts the response from the ClearlyDefined API to a dictionary of licenses.
    /// </summary>
    /// <param name="httpResponse"> The response from a ClearlyDefined API request.</param>
    public IDictionary<string, string> ConvertClearlyDefinedApiResponseToList(string httpResponseContent);

    /// <summary>
    /// Appends the licenses from the partialLicenseDictionary to the licenseDictionary.
    /// We only request license information for 400 components at a time so we can end up with multiple responses. This function is used to combine the responses into a single dictionary.
    /// </summary>
    /// <param name="partialLicenseDictionary"> A dictionary of licenses and component names in the {name@version, license} format</param>
    public void AppendLicensesToDictionary(IDictionary<string, string> partialLicenseDictionary);

    /// <summary>
    /// Gets the license from the licenseDictionary.
    /// </summary>
    /// <param name="key">The "name@version" of a component.</param>
    public string GetFromLicenseDictionary(string key);
}
