// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions;

namespace Microsoft.Sbom.Api.Workflows.Helpers;

public interface IJsonSerializationStrategy
{
    public void AddToFilesSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public void AddToPackagesSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public bool AddToRelationshipsSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public void AddToExternalDocRefsSupportingConfig(ref IList<ISbomConfig> elementsSupportingConfigs, ISbomConfig config);

    public void AddHeadersToSbom(ISbomConfigProvider sbomConfigs)
    {
    }

    public Task<List<FileValidationResult>> WriteJsonObjectsToSbomAsync(
        ISbomConfig sbomConfig,
        string spdxManifestVersion,
        IJsonArrayGenerator<FileArrayGenerator> fileArrayGenerator,
        IJsonArrayGenerator<PackageArrayGenerator> packageArrayGenerator,
        IJsonArrayGenerator<RelationshipsArrayGenerator> relationshipsArrayGenerator,
        IJsonArrayGenerator<ExternalDocumentReferenceGenerator> externalDocumentReferenceGenerator);
}
