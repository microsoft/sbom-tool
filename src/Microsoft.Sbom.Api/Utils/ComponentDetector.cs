// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Common;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Orchestrator;
using Microsoft.ComponentDetection.Orchestrator.Services;
using Microsoft.Extensions.Logging;

namespace Microsoft.Sbom.Api.Utils;

/// <summary>
/// A component detector wrapper, used for unit testing.
/// </summary>
public class ComponentDetector : IComponentDetector
{
    private readonly IServiceProvider serviceProvider;
    private readonly IEnumerable<IArgumentHandlingService> argumentHandlers;
    private readonly IFileWritingService fileWritingService;
    private readonly IArgumentHelper argumentHelper;
    private readonly ILogger<Orchestrator> logger;

    public ComponentDetector(
        IServiceProvider serviceProvider,
        IEnumerable<IArgumentHandlingService> argumentHandlers,
        IFileWritingService fileWritingService,
        IArgumentHelper argumentHelper,
        ILogger<Orchestrator> logger)
    {
        this.serviceProvider = serviceProvider;
        this.argumentHandlers = argumentHandlers;
        this.fileWritingService = fileWritingService;
        this.argumentHelper = argumentHelper;
        this.logger = logger;
    }

    public virtual async Task<ScanResult> ScanAsync(string[] args)
    {
        var orchestrator = new Orchestrator(
            serviceProvider,
            argumentHandlers,
            fileWritingService,
            argumentHelper,
            logger);

        return await orchestrator.LoadAsync(args);
    }
}