// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.PackageDetails;

public interface IPackageDetailsFactory
{
    /// <summary>
    /// Takes in a list of ScannedComponents and returns a dictionary where the key is the component name and version and the value is PackageDetails record which is made up of information found in the package files.
    /// </summary>
    /// <param name="scannedComponents">An IEnumerable of ScannedComponents which is the output of a component-detection scan.</param>
    /// <returns></returns>
    IDictionary<(string Name, string Version), PackageDetails> GetPackageDetailsDictionary(IEnumerable<ScannedComponent> scannedComponents);
}
