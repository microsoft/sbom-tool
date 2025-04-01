// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.ComplianceStandard;

internal class ComplianceExtensions
{
    /// <summary>
    /// Get the entity type based on the compliance standard.
    /// For example, for files that are validated with the NTIA compliance standard, the entity type is "NTIAFile".
    /// </summary>
    internal static string GetCommonEntityType(string entityType)
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
