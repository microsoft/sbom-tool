// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Workflows;

using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions;

public interface ISbomValidationWorkflowFactory
{
    public IWorkflow<SbomParserBasedValidationWorkflow> Get(IConfiguration configuration, ISbomConfig sbomConfig, string eventName);
}
