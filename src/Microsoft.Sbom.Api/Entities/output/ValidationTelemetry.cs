// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Entities.Output;

public class ValidationTelemetry
{
    /// <summary>
    /// Gets or sets count of files that were successful.
    /// </summary>
    public int FilesSuccessfulCount { get; set; }

    /// <summary>
    /// Gets or sets total files in the manifest file.
    /// </summary>
    public int TotalFilesInManifest { get; set; }

    /// <summary>
    /// Gets or sets count of files that were validated.
    /// </summary>
    public int FilesValidatedCount { get; set; }

    /// <summary>
    /// Gets or sets count of files that were skipped.
    /// </summary>
    public int FilesSkippedCount { get; set; }

    /// <summary>
    /// Gets or sets count of files that failed validation.
    /// </summary>
    public int FilesFailedCount { get; set; }

    public int TotalPackagesInManifest { get; set; }
}
