// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Channels;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Executors;

/// <summary>
/// Interface to read read SBOM file. Implement this class for different formats of SBOM file.
/// </summary>
public interface ISbomReaderForExternalDocumentReference
{
    (ChannelReader<ExternalDocumentReferenceInfo> results, ChannelReader<FileValidationResult> errors) ParseSbomFile(ChannelReader<string> sbomFileLocation);
}
