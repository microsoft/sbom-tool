// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;
using Microsoft.Sbom.Parsers.Spdx30SbomParser.ConformanceStandard.Interfaces;

namespace Microsoft.Sbom.Common.ConformanceStandard;

public class NoneConformanceStandardEnforcer : IConformanceStandardEnforcer
{
    public ConformanceStandardType ConformanceStandard => ConformanceStandardType.None;

    public string GetConformanceStandardEntityType(string entityType)
    {
        return entityType.GetCommonEntityType();
    }

    public void AddInvalidElementsIfDeserializationFails(string jsonObjectAsString, JsonSerializerOptions jsonSerializerOptions, HashSet<InvalidElementInfo> invalidElements, Exception e)
    {
        throw new ParserException(e.Message);
    }

    public void AddInvalidElements(ElementsResult elementsResult)
    {
        return;
    }
}
