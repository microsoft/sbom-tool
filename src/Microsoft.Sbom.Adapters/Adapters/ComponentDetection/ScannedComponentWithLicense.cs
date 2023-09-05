// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;

public class ScannedComponentWithLicense : ScannedComponent
{
    public string? License { get; set; }

    public SbomPackage? ToSbomPackage(AdapterReport report)
    {
        return ScannedComponentExtensions.ToSbomPackage(this, report);
    }

    // Copy constructor
    public ScannedComponentWithLicense(ScannedComponent? other = null)
        : base() // Call the base class constructor
    {
        if (other != null)
        {
            // Copy properties from the base class
            LocationsFoundAt = other.LocationsFoundAt;
            Component = other.Component;
            ContainerDetailIds = other.ContainerDetailIds;
            DependencyScope = other.DependencyScope;
            ContainerLayerIds = other.ContainerLayerIds;
            DetectorId = other.DetectorId;
            IsDevelopmentDependency = other.IsDevelopmentDependency;
            TopLevelReferrers = other.TopLevelReferrers;
        }
    }
}
