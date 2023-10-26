// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;

/// <summary>
/// A <see cref="ScannedComponent" /> with license information.
/// </summary>
public class ExtendedScannedComponent : ScannedComponent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ExtendedScannedComponent" /> class.
    /// </summary>
    /// <param name="other">The <see cref="ScannedComponent" /> to copy properties from.</param>
    public ExtendedScannedComponent(ScannedComponent? other = null)
    {
        if (other == null)
        {
            return;
        }

        // Copy properties from the base class
        this.LocationsFoundAt = other.LocationsFoundAt;
        this.Component = other.Component;
        this.ContainerDetailIds = other.ContainerDetailIds;
        this.DependencyScope = other.DependencyScope;
        this.ContainerLayerIds = other.ContainerLayerIds;
        this.DetectorId = other.DetectorId;
        this.IsDevelopmentDependency = other.IsDevelopmentDependency;
        this.TopLevelReferrers = other.TopLevelReferrers;
    }

    /// <summary>
    /// Gets or sets the license concluded which is retrieved from the ClearlyDefined API.
    /// </summary>
    public string? LicenseConcluded { get; set; }

    /// <summary>
    /// Gets or sets the license declared which is found directly in the package metadata.
    /// </summary>
    public string? LicenseDeclared { get; set; }

    /// <summary>
    /// Gets or sets the supplier.
    /// </summary>
    public string? Supplier { get; set; }

    /// <summary>
    /// Converts a <see cref="ExtendedScannedComponent" /> to an <see cref="SbomPackage" />.
    /// </summary>
    /// <param name="report">The <see cref="AdapterReport" /> to use.</param>
    /// <returns>The converted <see cref="SbomPackage" />.</returns>
    public SbomPackage? ToSbomPackage(AdapterReport report) => ScannedComponentExtensions.ToSbomPackage(this, report);
}
