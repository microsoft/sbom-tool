// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Executors;

using Microsoft.Sbom.Extensions.Entities;

public interface ISbomReferenceDescriber
{
    public bool IsSupportedFormat(string sbomFilePath);

    public ExternalDocumentReferenceInfo CreateExternalDocumentRefererence(string sbomFilePath);
}
