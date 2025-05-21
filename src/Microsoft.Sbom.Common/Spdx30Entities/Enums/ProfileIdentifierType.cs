// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Common.Spdx30Entities.Enums;

/// <summary>
/// There are a set of profiles that have been defined by a profile team.
/// https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/ProfileIdentifierType/.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
[SuppressMessage(
    "StyleCop.CSharp.NamingRules",
    "SA1300:Element should begin with upper-case letter",
    Justification = "These are enum types that are case sensitive and defined by external code.")]
public enum ProfileIdentifierType
{
    ai,
    build,
    core,
    dataset,
    expandedLicensing,
    extension,
    lite,
    security,
    simpleLicensing,
    software
}
