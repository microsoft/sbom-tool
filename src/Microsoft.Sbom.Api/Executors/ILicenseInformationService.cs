// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Executors;

public interface ILicenseInformationService
{
    public Task<List<string>> FetchLicenseInformationFromAPI(List<string> listOfComponentsForApi, int timeoutInSeconds);
}
