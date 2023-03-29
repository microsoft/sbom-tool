// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Workflows
{
    /// <summary>
    /// Defines the workflow run for a given action.
    /// </summary>
    public interface IWorkflow<T>
        where T : IWorkflow<T>
    {
        public Task<bool> RunAsync();
    }
}