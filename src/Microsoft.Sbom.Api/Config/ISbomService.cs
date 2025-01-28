// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Config.Args;

namespace Microsoft.Sbom.Api.Config;

/// <summary>
/// Marker interface for an SBOM service.
/// </summary>
/// <typeparam name="T">The type of arguments against which this service is run.</typeparam>
#pragma warning disable CA1040 // Avoid empty interfaces
public interface ISbomService<T>
#pragma warning restore CA1040 // Avoid empty interfaces
    where T : CommonArgs
{
}
