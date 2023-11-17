// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Object used to define the information extracted from package metadata files.
/// </summary>
/// <param name="License">The license declared by the package in its own metadata file.</param>
/// <param name="Supplier">The people/company who are listed in the package as the author or supplier.</param>
public record PackageDetails(string License, string Supplier);
