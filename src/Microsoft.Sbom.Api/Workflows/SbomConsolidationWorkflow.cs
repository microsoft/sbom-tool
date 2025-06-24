// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Workflows;

using System.Threading.Tasks;

public class SbomConsolidationWorkflow : IWorkflow<SbomConsolidationWorkflow>
{
    /// <inheritdoc/>
#pragma warning disable CS1998 // Placeholder, will use async in the future.
    public virtual async Task<bool> RunAsync() => true;
#pragma warning restore CS1998 // Placeholder, will use async in the future.
}
