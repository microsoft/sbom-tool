// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Reflection;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Api.Config.Args;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config;

[ArgDescription("The Sbom tool generates a SBOM for any build artifact.")]
[ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling)]
[ArgProductName("sbom-tool")]
public class SbomToolCmdRunner
{
    internal static string SbomToolVersion => VersionValue.Value;

    private static readonly Lazy<string> VersionValue = new Lazy<string>(() =>
    {
        return typeof(SbomToolCmdRunner).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty;
    });

    /// <summary>
    /// Gets or sets a value indicating whether displays help info.
    /// </summary>
    [ArgShortcut("?")]
    [ArgShortcut("h")]
    [HelpHook]
    [JsonIgnore]
    [ArgDescription("Prints this help message")]
    public bool Help { get; set; }

    /// <summary>
    /// Validate a build artifact using the manifest. Optionally also verify the signing certificate of the manifest.
    /// </summary>
    /// <param name="validationArgs"></param>
    [ArgActionMethod]
    [ArgDescription("Validate a build artifact using the manifest. " +
                    "Optionally also verify the signing certificate of the manifest.")]
    public ValidationArgs Validate(ValidationArgs validationArgs)
    {
        return validationArgs;
    }

    /// <summary>
    /// Validate a build artifact using the manifest. Optionally also verify the signing certificate of the manifest.
    /// </summary>
    /// <param name="validationArgs"></param>
    [ArgShortcut("validate-format")]
    [ArgShortcut("vf")]
    [ArgActionMethod]
    [ArgDescription("Validate the version and format of the SBOM")]
    [OmitFromUsageDocs]
    public FormatValidationArgs ValidateFormat(FormatValidationArgs validationArgs)
    {
        return validationArgs;
    }

    /// <summary>
    /// Generate a manifest.json and a bsi.json for all the files in the given build drop folder.
    /// </summary>
    [ArgActionMethod]
    [ArgDescription("Generate a SBOM for all the files " +
                    "in the given build drop folder, and the packages in the components path.")]
    public GenerationArgs Generate(GenerationArgs generationArgs)
    {
        return generationArgs;
    }

    /// <summary>
    /// Redact file information from given SBOM(s).
    /// </summary>
    [ArgActionMethod]
    [ArgDescription("Redact file information from given SBOM(s).")]
    public RedactArgs Redact(RedactArgs redactArgs)
    {
        return redactArgs;
    }

    /// <summary>
    /// Aggregate multiple SBOMs into a single SBOM.
    /// </summary>
    [ArgActionMethod]
    [ArgDescription("Aggregate multiple SBOMs into a single SBOM.")]
    public AggregationArgs Aggregate(AggregationArgs aggregationArgs)
    {
        return aggregationArgs;
    }

    /// <summary>
    /// Prints the version of the tool.
    /// </summary>
    [ArgActionMethod]
    [ArgShortcut("--version")]
    [ArgDescription("Displays the version of the tool being used. Can be used as '--version'")]
    public void Version()
    {
        if (!string.IsNullOrEmpty(SbomToolVersion))
        {
            Console.WriteLine(SbomToolVersion);
        }
        else
        {
            Console.WriteLine("Encountered error while getting the version of the tool.");
        }
    }
}
