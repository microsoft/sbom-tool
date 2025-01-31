// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config;
using Serilog;

namespace Microsoft.Sbom.Api.Workflows;

/// <summary>
/// The SBOM tool workflow class that is used to redact file information from a SBOM or set of SBOMs.
/// </summary>
public class SbomRedactionWorkflow : IWorkflow<SbomRedactionWorkflow>
{
    private readonly ILogger log;

    private readonly IConfiguration configuration;

    private readonly IFileSystemUtils fileSystemUtils;

    private readonly ValidatedSBOMFactory validatedSBOMFactory;

    private readonly ISbomRedactor sbomRedactor;

    public SbomRedactionWorkflow(
        ILogger log,
        IConfiguration configuration,
        IFileSystemUtils fileSystemUtils,
        ValidatedSBOMFactory validatedSBOMFactory,
        ISbomRedactor sbomRedactor)
    {
        this.log = log ?? throw new ArgumentNullException(nameof(log));
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        this.validatedSBOMFactory = validatedSBOMFactory ?? throw new ArgumentNullException(nameof(validatedSBOMFactory));
        this.sbomRedactor = sbomRedactor ?? throw new ArgumentNullException(nameof(sbomRedactor));
    }

    public virtual async Task<bool> RunAsync()
    {
        ValidateDirStrucutre();
        var sbomPaths = GetInputSbomPaths();
        foreach (var sbomPath in sbomPaths)
        {
            IValidatedSBOM validatedSbom = null;
            try
            {
                log.Information($"Validating SBOM {sbomPath}");
                validatedSbom = validatedSBOMFactory.CreateValidatedSBOM(sbomPath);
                var validationDetails = await validatedSbom.GetValidationResults();
                if (validationDetails.Status != FormatValidationStatus.Valid)
                {
                    throw new InvalidDataException($"Failed to validate {sbomPath}:\n{string.Join('\n', validationDetails.Errors)}");
                }
                else
                {
                    log.Information($"Redacting SBOM {sbomPath}");
                    var outputPath = GetOutputPath(sbomPath);
                    var redactedSpdx = await this.sbomRedactor.RedactSBOMAsync(validatedSbom);
                    using (var outStream = fileSystemUtils.OpenWrite(outputPath))
                    {
                        await JsonSerializer.SerializeAsync(outStream, redactedSpdx);
                    }

                    log.Information($"Redacted SBOM {sbomPath} saved to {outputPath}");
                }
            }
            finally
            {
                validatedSbom?.Dispose();
            }
        }

        return true;
    }

    private string GetOutputPath(string sbomPath)
    {
        return fileSystemUtils.JoinPaths(configuration.OutputPath.Value, fileSystemUtils.GetFileName(sbomPath));
    }

    private IEnumerable<string> GetInputSbomPaths()
    {
        if (configuration.SbomPath?.Value != null)
        {
            return new List<string>() { configuration.SbomPath.Value };
        }
        else if (configuration.SbomDir?.Value != null)
        {
            return fileSystemUtils.GetFilesInDirectory(configuration.SbomDir.Value);
        }
        else
        {
            throw new Exception("No valid input SBOMs to redact provided.");
        }
    }

    private string ValidateDirStrucutre()
    {
        string inputDir;
        if (configuration.SbomDir?.Value != null && fileSystemUtils.DirectoryExists(configuration.SbomDir.Value))
        {
            inputDir = configuration.SbomDir.Value;
        }
        else if (configuration.SbomPath?.Value != null && fileSystemUtils.FileExists(configuration.SbomPath.Value))
        {
            inputDir = fileSystemUtils.GetDirectoryName(configuration.SbomPath.Value);
        }
        else
        {
            throw new ArgumentException("No valid input SBOMs to redact provided.");
        }

        var outputDir = configuration.OutputPath.Value;
        if (fileSystemUtils.GetFullPath(outputDir).Equals(fileSystemUtils.GetFullPath(inputDir)))
        {
            throw new ArgumentException("Output path cannot be the same as input SBOM directory.");
        }

        if (!fileSystemUtils.DirectoryExists(outputDir))
        {
            fileSystemUtils.CreateDirectory(outputDir);
        }

        foreach (var sbom in GetInputSbomPaths())
        {
            var outputPath = GetOutputPath(sbom);
            if (fileSystemUtils.FileExists(outputPath))
            {
                throw new ArgumentException($"Output file {outputPath} already exists. Please update and try again.");
            }
        }

        return outputDir;
    }
}
