// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;

namespace Microsoft.Sbom.Api.PackageDetails;

public interface IPackageManagerUtils<T>
    where T : IPackageManagerUtils<T>
{
    /// <summary>
    /// Takes in a ScannedComponent object and attempts to find the corresponding .pom file.
    /// </summary>
    /// <param name="scannedComponent">A single <see cref="ScannedComponent"/> from a component detection scan.</param>
    /// <returns></returns>
    public string GetMetadataLocation(ScannedComponent scannedComponent);

    /// <summary>
    /// Takes in the path to a package metadata file (ex: .nuspec, .pom) file and returns a tuple consisting of the package name, version, and details such as its license and supplier.
    /// </summary>
    /// <param name="pomLocation">Path to a package metadata file.</param>
    /// <returns>A tuple containing the name, version, and <see cref="PackageDetails"/> of the specified metadata file.</returns>
    public (string Name, string Version, PackageDetails packageDetails) ParseMetadata(string pomLocation);
}
