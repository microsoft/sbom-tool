# Migrating to the Version 4 API from earlier versions

We introduced breaking changes in version 4 of the API. Some of these were necessary as part of refactoring to add SPDX 3.0 support. Others were more cosmetic, so we waited for a breaking change to add them.

## Functional changes

If you use the Workflows that are documented [here](sbom-tool-cli-reference.md), then you will not be impacted by most of the functional changes. You will get the default implementations of the classes and will probably only need to worry about the [cosmetic changes](#cosmetic-changes). If, however, you create your own implementations or wrappers based on any of the interfaces exposed in our API, then you will likely need to make some more significant changes in your code. This table summarizes the changes:

## Cosmetic changes

A customer pointed our that our naming conventions were somewhat inconsistent. The interfaces and classes that were written very early tended to spell "sbom" as "SBOM" (all caps), while code added later tended to use "Sbom" (Pascal case). Casing of the file names were similarly inconsistent. We decided to take this opportunity to adopt "Sbom" as our standard within the code (this matches the namespace), but still retain "SBOM" as the standalone form in documentation and comments. We haven't yet updated all of the test classes, but that should be a non-issue to users of the API. The "quick and dirty" change in your code is to do a case-sensitive global replacement of "SBOM" with "Sbom". The following table describes the cosmetic changes--this list is intended to be exhaustive and includes interfaces and classes that very few people would ever need to worry about:

Old (all caps) construct | New (Pascal case) construct
--- | ---
`ComponentDetectionToSBOMPackageAdapter` | `ComponentDetectionToSbomPackageAdapter`
`Events.SBOMGenerationWorkflow` | `Events.SbomGenerationWorkflow`
`Events.SBOMParseMetadata` | `Events.SbomParseMetadata`
`Events.SBOMValidationWorkflow` | `Events.SbomValidationWorkflow`
`FileHashes.SBOMFileHash` | `FileHashes.SbomFileHash`
`IAssemblyConfig.DefaultSBOMNamespaceBaseUri` | `IAssemblyConfig.DefaultSbomNamespaceBaseUri`
`IInternalMetadataProvider.GetSBOMNamespaceUri` | `IInternalMetadataProvider.GetSbomNamespaceUri`
`IRecorder.RecordSBOMFormat` | `IRecorder.RecordSbomFormat`
`ISBOMGenerator` | `ISbomGenerator`
`ISBOMGenerator.GetSupportedSBOMSpecifications` | `ISbomGenerator.GetSupportedSbomSpecifications`
`ISBOMReaderForExternalDocumentReference` | `ISbomReaderForExternalDocumentReference`
`ISBOMReaderForExternalDocumentReference.ParseSBOMFile` | `ISbomReaderForExternalDocumentReference.ParseSbomFile`
`ISBOMValidator` | `ISbomValidator`
`ISbomRedactor.RedactSBOMAsync` | `ISbomRedactor.RedactSbomAsync`
`IValidatedSBOM` | `IValidatedSbom`
`InternalSBOMFileInfoDeduplicator` | `InternalSbomFileInfoDeduplicator`
`MetadataKey.SBOMToolName` | `MetadataKey.SbomToolName`
`MetadataKey.SBOMToolVersion` | `MetadataKey.SbomToolVersion`
`SBOMApiMetadataProvider` | `SbomApiMetadataProvider`
`SBOMComponentsWalker` | `SbomComponentsWalker`
`SBOMFile` | `SbomFile`
`SBOMFormatExtensions` | `SbomFormatExtensions`
`ManifestInfo.ToSBOMSpecification` | `ManifestInfo.ToSbomSpecification`
`SBOMMetadata` | `SbomMetadata`
`SBOMPackagesProvider` | `SbomPackagesProvider`
`SBOMReference` | `SbomReference`
`SBOMRelationship` | `SbomRelationship`
`SBOMTelemetry` | `SbomTelemetry`
`SBOMValidationResult` | `SbomValidationResult`
`SPDXSBOMReaderForExternalDocumentReference` | `SPDXSbomReaderForExternalDocumentReference`
`SPDXSBOMReaderForExternalDocumentReference.ParseSBOMFile` | `SPDXSbomReaderForExternalDocumentReference.ParseSbomFile`
`SbomConfigProvider.GetSBOMNamespaceUri` | `SbomConfigProvider.GetSbomNamespaceUri`
`SbomGenerator.GetSupportedSBOMSpecifications` | `SbomGenerator.GetSupportedSbomSpecifications`
`SbomRedactor.RedactSBOMAsync` | `SbomRedactor.RedactSbomAsync`
`SettingsSource.SBOMApi` | `SettingsSource.SbomApi`
`TelemetryRecorder.RecordSBOMFormat` | `TelemetryRecorder.RecordSbomFormat`
`ValidatedSBOM` | `ValidatedSbom`
`ValidatedSBOMFactory` | `ValidatedSbomFactory`
`ValidatedSBOMFactory.CreateValidatedSBOM` | `ValidatedSbomFactory.CreateValidatedSbom`

We discussed making a similar change with "SPDX", but ultimately decided to leave "SPDX" as all caps when dealing with interfaces and classes. There are many places in the code where variables use either camel casing or Pascal casing, but none of those should impact code that builds upon our API.

