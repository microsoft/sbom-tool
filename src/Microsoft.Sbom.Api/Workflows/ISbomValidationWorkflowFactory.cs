// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows;

public interface ISbomValidationWorkflowFactory
{
    public IWorkflow<SbomParserBasedValidationWorkflow> Get(IConfiguration configuration, ISbomConfig sbomConfig, string eventName);
}
