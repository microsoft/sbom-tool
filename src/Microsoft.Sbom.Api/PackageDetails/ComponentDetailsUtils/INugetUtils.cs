// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.PackageDetails;

public interface INugetUtils
{
    /// <summary>
    /// Takes in a ScannedComponent object and attempts to find the corresponding .nuspec file.
    /// </summary>
    /// <param name="scannedComponent">A single <see cref="ScannedComponent"/> from a component detection scan.</param>
    /// <returns>The file path to the .nuspec as a string.</returns>
    public string GetNuspecLocation(ScannedComponent scannedComponent);

    /// <summary>
    /// Takes in the path to a .nuspec file and returns a tuple consisting of the package name, version, and details such as its license and supplier.
    /// </summary>
    /// <param name="nuspecPath">Path to a .nuspec file.</param>
    /// <returns>A tuple containing the name, version, and <see cref="PackageDetails"/> of the specified .nuspec.</returns>
    public (string Name, string Version, PackageDetails packageDetails) ParseNuspec(string nuspecPath);
}
