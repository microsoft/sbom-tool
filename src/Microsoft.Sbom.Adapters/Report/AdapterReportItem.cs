// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Adapters.Report;

/// <summary>
/// Represents the type of report being created.
/// </summary>
public enum AdapterReportItemType
{
    Success = 0,
    Failure = 1,
    Warning = 2,
}

/// <summary>
/// A single adapter report item.
/// </summary>
public class AdapterReportItem
{
    public AdapterReportItemType Type { get; set; }

    public string Details { get; set; }

    public AdapterReportItem(AdapterReportItemType type, string details)
    {
        Type = type;
        Details = details ?? throw new ArgumentNullException(nameof(details));
    }
}
