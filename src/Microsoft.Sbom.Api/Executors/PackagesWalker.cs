﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using System.Collections.Generic;
using System.Linq;
using ILogger = Serilog.ILogger;

namespace Microsoft.Sbom.Api.Executors
{
    /// <summary>
    /// Runs the component detection tool and returns a list of components scanned in the given folder.
    /// </summary>
    public class PackagesWalker : ComponentDetectionBaseWalker
    {
        public PackagesWalker(ILogger log, ComponentDetectorCachedExecutor componentDetector, IConfiguration configuration, ISbomConfigProvider sbomConfigs)
            : base(log, componentDetector, configuration, sbomConfigs)
        {
        }

        protected override IEnumerable<ScannedComponent> FilterScannedComponents(ScanResult result)
        {
            return result
                .ComponentsFound
                .Where(component => !(component.Component is SpdxComponent)) // We exclude detected SBOMs from packages section and reference them as an ExternalReference
                .Distinct(new ScannedComponentEqualityComparer())
                .ToList();
        }
    }
}
