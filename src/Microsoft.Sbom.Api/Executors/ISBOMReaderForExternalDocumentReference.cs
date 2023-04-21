// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Channels;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Entities;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Interface to read read SBOM file. Implement this class for different formats of SBOM file.
/// </summary>
public interface ISBOMReaderForExternalDocumentReference
{
    (ChannelReader<ExternalDocumentReferenceInfo> results, ChannelReader<FileValidationResult> errors) ParseSBOMFile(ChannelReader<string> sbomFileLocation);
}