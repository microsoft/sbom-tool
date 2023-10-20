// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Adapters.ComponentDetection;

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

/// <summary>
/// A <see cref="ScanResult" /> with license information.
/// </summary>
[JsonObject(MemberSerialization.OptOut, NamingStrategyType = typeof(CamelCaseNamingStrategy))]
public sealed class ScanResultWithExtendedComponent : ScanResult
{
    /// <summary>
    /// Gets or sets the scanned components with license information.
    /// </summary>
    public new IEnumerable<ExtendedScannedComponent>? ComponentsFound { get; init; }
}
