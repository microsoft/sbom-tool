// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Build.Framework;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Tool;
using PowerArgs;
using Task = Microsoft.Build.Utilities.Task;

namespace Microsoft.Sbom.Targets;

public class GenerateSbomTask : Task
{
    [Required]
    public string BuildDropPath { get; set; }

    [Required]
    public string BuildComponentPath { get; set; }

    [Required]
    public string PackageSupplier { get; set; }

    [Required]
    public string PackageName { get; set; }

    [Required]
    public string PackageVersion { get; set; }

    [Output]
    public string SbomPath { get; set; }

    public override bool Execute()
    {
        if (string.IsNullOrEmpty(BuildDropPath) ||
            string.IsNullOrEmpty(BuildComponentPath) ||
            string.IsNullOrEmpty(PackageSupplier) ||
            string.IsNullOrEmpty(PackageName) ||
            string.IsNullOrEmpty(PackageVersion))
        {
            Log.LogError("Required argument not provided.");
            return false;
        }

        try
        {
            // TODO setup suggested by docs
            // await Host.CreateDefaultBuilder(args)
            //    .ConfigureServices((host, services) =>
            //    {
            //        services
            //        .AddHostedService<GenerationService>()
            //        .AddSbomTool();
            //    })
            //    .RunConsoleAsync(x => x.SuppressStatusMessages = true);
            SbomPath = "path/to/sbom";
            return true;
        }
        catch (Exception e)
        {
            Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }
}
