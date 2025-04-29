// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Conformance;
using Microsoft.Sbom.Contracts.Enums;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Conformance.Interfaces;

public interface IConformanceStandardEnforcer
{
    public ConformanceStandardType ConformanceStandard { get; }

    public string GetConformanceStandardEntityType(string entityType);

    public void AddInvalidElementsIfDeserializationFails(string jsonObjectAsString, JsonSerializerOptions jsonSerializerOptions, HashSet<InvalidElementInfo> invalidElements, Exception e);

    public void AddInvalidElements(ElementsResult elementsResult);
}
