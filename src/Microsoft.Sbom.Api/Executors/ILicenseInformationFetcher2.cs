// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors;

public interface ILicenseInformationFetcher2: ILicenseInformationFetcher
{
    /// <summary>
    /// Calls the ClearlyDefined API to get the license information for the list of components.
    /// </summary>
    /// <param name="listOfComponentsForApi"> A list of strings formatted into a list of strings that can be used to call the batch ClearlyDefined API.</param>
    /// <param name="timeoutInSeconds">Timeout in seconds to use when making web requests</param>
    /// <returns></returns>
    Task<List<string>> FetchLicenseInformationAsync(List<string> listOfComponentsForApi, int timeoutInSeconds);
}
