// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.ConformanceStandard;

internal static class ComplianceExtensions
{
    /// <summary>
    /// Gets the common entity type that is used by the parser.
    /// </summary>
    internal static string GetCommonEntityType(this string entityType)
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
}
