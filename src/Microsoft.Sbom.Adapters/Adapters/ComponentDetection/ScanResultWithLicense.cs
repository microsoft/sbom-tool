// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

[JsonObject(MemberSerialization.OptOut, NamingStrategyType = typeof(CamelCaseNamingStrategy))]
public sealed class ScanResultWithLicense : ScanResult
{
    public new IEnumerable<ScannedComponentWithLicense>? ComponentsFound { get; init; }
}