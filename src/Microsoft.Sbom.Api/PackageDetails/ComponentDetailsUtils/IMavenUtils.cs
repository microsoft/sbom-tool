// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.PackageDetails;

public interface IMavenUtils
{
    /// <summary>
    /// Takes in a ScannedComponent object and attempts to find the corresponding .pom file.
    /// </summary>
    /// <param name="scannedComponent">A single <see cref="ScannedComponent"/> from a component detection scan.</param>
    /// <returns></returns>
    public string GetPomLocation(ScannedComponent scannedComponent);

    /// <summary>
    /// Takes in the path to a .pom file and returns a tuple consisting of the package name, version, and details such as its license and supplier.
    /// </summary>
    /// <param name="pomLocation">Path to a .pom file.</param>
    /// <returns>A tuple containing the name, version, and <see cref="PackageDetails"/> of the specified .pom file.</returns>
    public (string Name, string Version, PackageDetails packageDetails) ParsePom(string pomLocation);
}
