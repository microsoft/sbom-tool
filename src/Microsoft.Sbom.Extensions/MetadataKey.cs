// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Extensions.Entities;

/// <summary>
/// A list of keys that are available as metadata in the internal metadata provider.
/// </summary>
public enum MetadataKey
{
    /// <summary>
    /// The name of the tool that generated this SBOM.
    /// </summary>
    SbomToolName,

    /// <summary>
    /// The version of the tool that generated this SBOM.
    /// </summary>
    SbomToolVersion,

    /// <summary>
    /// The name of the package this SBOM represents.
    /// </summary>
    PackageName,

    /// <summary>
    /// The version of the package this SBOM represents.
    /// </summary>
    PackageVersion,

    /// <summary>
    /// The supplier of the package this SBOM represents.
    /// </summary>
    PackageSupplier,

    /// <summary>
    /// The name of the build environment, like ADO or cloudbuild.
    /// </summary>
    BuildEnvironmentName,

    /// <summary>
    /// The timestamp that should be used for the generation timestamp of the SBOM instead of
    /// the current time.
    /// </summary>
    GenerationTimestamp,

    /// <summary>
    /// Please note these variables will be empty when the SBOM generator
    /// is not run inside an Azure DevOps Pipeline. For more information about
    /// these variables, go to
    /// https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#build-variables-devops-services
    /// </summary>
    Build_BuildId,
    Build_DefinitionName,
    Build_Repository_Uri,
    Build_SourceBranchName,
    Build_SourceVersion,
    System_DefinitionId,
    ImageOS,
    ImageVersion,
    OrganizationId,
    ProjectId
}
