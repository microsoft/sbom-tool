// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;

namespace Microsoft.Sbom.Api.Entities.Output;

/// <summary>
/// Generates a <see cref="ValidationResult"/> object.
/// </summary>
public class ValidationResultGenerator
{
    private int successCount;
    private int totalFiles;
    private int totalPackages;
    private TimeSpan duration;
    private readonly IConfiguration configuration;

    public IList<FileValidationResult> NodeValidationResults { get; set; }

    public ValidationResultGenerator(IConfiguration configuration)
    {
        this.configuration = configuration;
    }

    /// <summary>
    /// Sets the count of successful results.
    /// Retuns the <see cref="ValidationResultGenerator"/> for chaining.
    /// </summary>
    /// <param name="successCount"></param>
    /// <returns><see cref="ValidationResultGenerator"/>.</returns>
    public ValidationResultGenerator WithSuccessCount(int successCount)
    {
        this.successCount = successCount;
        return this;
    }

    /// <summary>
    /// Sets the total duration the validator ran..
    /// Retuns the <see cref="ValidationResultGenerator"/> for chaining.
    /// </summary>
    /// <param name="duration"></param>
    /// <returns><see cref="ValidationResultGenerator"/>.</returns>
    public ValidationResultGenerator WithTotalDuration(TimeSpan duration)
    {
        this.duration = duration;
        return this;
    }

    /// <summary>
    /// Sets the failed validation results.
    /// Retuns the <see cref="ValidationResultGenerator"/> for chaining.
    /// </summary>
    /// <param name="nodeValidationResults"></param>
    /// <returns><see cref="ValidationResultGenerator"/>.</returns>
    public ValidationResultGenerator WithValidationResults(IList<FileValidationResult> nodeValidationResults)
    {
        NodeValidationResults = nodeValidationResults ?? new List<FileValidationResult>();
        return this;
    }

    /// <summary>
    /// Finalizes the validation generation and returns a new <see cref="ValidationResult"/> object.
    /// </summary>
    /// <returns></returns>
    public ValidationResult Build()
    {
        List<FileValidationResult> validationErrors;
        List<FileValidationResult> skippedErrors;

        validationErrors = NodeValidationResults.Where(r => !Constants.SkipFailureReportingForErrors.Contains(r.ErrorType)).ToList();
        skippedErrors = NodeValidationResults.Where(r => Constants.SkipFailureReportingForErrors.Contains(r.ErrorType)).ToList();

        if (configuration.IgnoreMissing.Value)
        {
            validationErrors.RemoveAll(e => e.ErrorType == ErrorType.MissingFile);
            skippedErrors.AddRange(NodeValidationResults.Where(r => r.ErrorType == ErrorType.MissingFile));
        }

        return new ValidationResult
        {
            Result = validationErrors.Count == 0 ? Result.Success : Result.Failure,
            ValidationErrors = new ErrorContainer<FileValidationResult>
            {
                Count = validationErrors.Count,
                Errors = validationErrors
            },
            Summary = new Summary
            {
                TotalExecutionTimeInSeconds = duration.TotalSeconds,
                ValidationTelemetery = new ValidationTelemetry
                {
                    FilesSuccessfulCount = successCount,
                    FilesValidatedCount = NodeValidationResults.Count + successCount,
                    FilesFailedCount = validationErrors.Where(r => r.ErrorType != ErrorType.NoPackagesFound).Count(),
                    FilesSkippedCount = skippedErrors.Count,
                    TotalFilesInManifest = totalFiles,
                    TotalPackagesInManifest = totalPackages
                },
                Parameters = configuration
            }
        };
    }

    public ValidationResultGenerator WithTotalFilesInManifest(int totalFiles)
    {
        this.totalFiles = totalFiles;
        return this;
    }

    public ValidationResultGenerator WithTotalPackagesInManifest(int totalPackages)
    {
        this.totalPackages = totalPackages;
        return this;
    }
}
