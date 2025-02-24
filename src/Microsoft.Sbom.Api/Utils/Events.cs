// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Utils;

internal static class Events
{
    internal const string SbomGenerationWorkflow = "Total generation time";
    internal const string SbomParseMetadata = "Total metadata parsing time";
    internal const string FilesGeneration = "Files generation time";
    internal const string PackagesGeneration = "Packages generation time";
    internal const string RelationshipsGeneration = "Relationships generation time";
    internal const string MetadataBuilder = "Metadata build time for {0} format";
    internal const string ExternalDocumentReferenceGeneration = "External document reference generation time";

    internal const string SBOMValidationWorkflow = "Total validation time";
}
