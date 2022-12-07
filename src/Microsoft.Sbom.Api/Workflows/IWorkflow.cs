// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Entities.Output;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows
{
    /// <summary>
    /// Defines the workflow run for a given action.
    /// </summary>
    public interface IWorkflow
    {
        public Task<ValidationResult> RunAsync();

    }
}
