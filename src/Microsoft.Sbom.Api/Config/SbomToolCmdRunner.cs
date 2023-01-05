// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System.Text.Json.Serialization;
using Microsoft.Sbom.Api.Config.Args;

namespace Microsoft.Sbom.Api.Config
{
    [ArgDescription("The Sbom tool generates a SBOM for any build artifact.")]
    [ArgExceptionBehavior(ArgExceptionPolicy.StandardExceptionHandling)]
    [ArgProductName("sbom-tool")]
    public class SbomToolCmdRunner
    {
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
        /// Validate a build artifact using the manifest. Optionally also verify the signing certificate of the manfiest.
        /// </summary>
        /// <param name="validationArgs"></param>
        [ArgActionMethod]
        [ArgDescription("Validate a build artifact using the manifest. " +
            "Optionally also verify the signing certificate of the manfiest.")]
        public ValidationArgs Validate(ValidationArgs validationArgs)
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
    }
}
