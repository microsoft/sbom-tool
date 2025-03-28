// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.ComplianceStandard;

using System;
using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.JsonAsynchronousNodeKit.Exceptions;

public abstract class ComplianceStandardEnforcer
{
    public virtual ComplianceStandardType ComplianceStandard { get; }

    /// <summary>
    /// Get the entity type based on the compliance standard.
    /// For example, for files that are validated with the NTIA compliance standard, the entity type is "NTIAFile".
    /// </summary>
    public virtual string GetComplianceStandardEntityType(string entityType)
    {
        // For these special cases, remove the prefix from the type.
        switch (entityType)
        {
            case "software_File":
                return "File";
            case "software_Package":
                return "Package";
            default:
                return entityType;
        }
    }

    public virtual void AddInvalidElementsIfDeserializationFails(string jsonObjectAsString, JsonSerializerOptions jsonSerializerOptions, HashSet<InvalidElementInfo> invalidElements, Exception e)
    {
        throw new ParserException(e.Message);
    }

    public virtual void AddInvalidElements(ElementsResult elementsResult)
    {
        return;
    }
}
