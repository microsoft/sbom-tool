// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Sbom.Adapters.Report;

/// <summary>
/// Contains a report of logging information recorded during adapter execution.
/// </summary>
public class AdapterReport
{
    /// <summary>
    /// Set of reported items for an adapter.
    /// </summary>
    public readonly List<AdapterReportItem> Report;

    /// <nodoc/>
    public AdapterReport()
    {
        Report = new List<AdapterReportItem>();
    }

    /// <nodoc/>
    public void LogSuccess()
    {
        Report.Add(new AdapterReportItem(AdapterReportItemType.Success, string.Empty));
    }

    /// <nodoc/>
    public void LogFailure(string details)
    {
        Report.Add(new AdapterReportItem(AdapterReportItemType.Failure, details));
    }

    /// <nodoc/>
    public void LogWarning(string details)
    {
        Report.Add(new AdapterReportItem(AdapterReportItemType.Warning, details));
    }
}