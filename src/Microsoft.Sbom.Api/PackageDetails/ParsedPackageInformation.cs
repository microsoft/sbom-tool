// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Object used to define the information extracted from package metadata files.
/// </summary>
/// <param name="Name">The name declared by the package in its own metadata file.</param>
/// <param name="Version">The version of the package being described by the metadata file.</param>
/// <param name="PackageDetails">The additional package details extracted from the metadata file.</param>
public record ParsedPackageInformation(string Name, string Version, PackageDetails PackageDetails);
