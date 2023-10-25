// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Orchestrator.Commands;
using Microsoft.ComponentDetection.Orchestrator.Services;
using Microsoft.ComponentDetection.Orchestrator.Services.GraphTranslation;
using Microsoft.Extensions.Logging;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// A component detector wrapper, used for unit testing.
/// </summary>
public class ComponentDetector : IComponentDetector
{
    private readonly IEnumerable<ComponentDetection.Contracts.IComponentDetector> detectors;
    private readonly IDetectorProcessingService detectorProcessingService;
    private readonly IDetectorRestrictionService detectorRestrictionService;
    private readonly IGraphTranslationService graphTranslationService;
    private readonly ILogger<ScanExecutionService> logger;

    public ComponentDetector(
        IEnumerable<ComponentDetection.Contracts.IComponentDetector> detectors,
        IDetectorProcessingService detectorProcessingService,
        IDetectorRestrictionService detectorRestrictionService,
        IGraphTranslationService graphTranslationService,
        ILogger<ScanExecutionService> logger)
    {
        this.detectors = detectors;
        this.detectorProcessingService = detectorProcessingService;
        this.detectorRestrictionService = detectorRestrictionService;
        this.graphTranslationService = graphTranslationService;
        this.logger = logger;
    }

    public virtual async Task<ScanResult> ScanAsync(ScanSettings args)
    {
        var executionService = new ScanExecutionService(
            detectors,
            detectorProcessingService,
            detectorRestrictionService,
            graphTranslationService,
            logger);

        return await executionService.ExecuteScanAsync(args);
    }
}
