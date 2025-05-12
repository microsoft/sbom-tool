# Migrating to the version 4 API from the version 3 API

This release includes breaking changes to the API. Most API consumers will be impacted by the [casing changes](#casing-changes). Only a few customers are likely to be impacted by the [functional changes](#functional-changes).

## Casing changes

The cases used in the 3.0 API were very inconsistent. The interfaces and classes that were written very early tended to spell "sbom" as "SBOM" (all caps), while code added later tended to use "Sbom" (Pascal case). Casing of the file names were similarly inconsistent. We decided to take this opportunity to adopt "Sbom" as our standard within the code (this matches the namespace), but still retain "SBOM" as the standalone form in documentation and comments. We haven't yet updated all of the test classes, but that should be a non-issue to users of the API. The "quick and dirty" change in your code is to do a case-sensitive global replacement of "SBOM" with "Sbom". The following table describes the detailed casing changes--this list is intended to be exhaustive and includes interfaces and classes that very few people would ever need to worry about:

### Interfaces

Old name (all caps) | New name (Pascal case)
--- | ---
`InternalSBOMFileInfoDeduplicator` | `InternalSbomFileInfoDeduplicator`
`ISBOMGenerator` | `ISbomGenerator`
`ISBOMReaderForExternalDocumentReference` | `ISbomReaderForExternalDocumentReference`
`ISBOMValidator` | `ISbomValidator`
`IValidatedSBOM` | `IValidatedSbom`

### Classes

Old name (all caps) | New name (Pascal case)
--- | ---
`ComponentDetectionToSBOMPackageAdapter` | `ComponentDetectionToSbomPackageAdapter`
`SBOMApiMetadataProvider` | `SbomApiMetadataProvider`
`SBOMComponentsWalker` | `SbomComponentsWalker`
`SBOMFile` | `SbomFile`
`SBOMFormatExtensions` | `SbomFormatExtensions`
`SBOMMetadata` | `SbomMetadata`
`SBOMPackagesProvider` | `SbomPackagesProvider`
`SBOMReference` | `SbomReference`
`SBOMRelationship` | `SbomRelationship`
`SBOMTelemetry` | `SbomTelemetry`
`SBOMValidationResult` | `SbomValidationResult`
`SPDXSBOMReaderForExternalDocumentReference` | `SPDXSbomReaderForExternalDocumentReference`
`ValidatedSBOM` | `ValidatedSbom`
`ValidatedSBOMFactory` | `ValidatedSbomFactory`

### Methods

Old name (all caps) | New name (Pascal case)
--- | ---
`IInternalMetadataProvider.GetSBOMNamespaceUri` | `IInternalMetadataProvider.GetSbomNamespaceUri`
`IRecorder.RecordSBOMFormat` | `IRecorder.RecordSbomFormat`
`ISBOMGenerator.GetSupportedSBOMSpecifications` | `ISbomGenerator.GetSupportedSbomSpecifications`
`ISBOMReaderForExternalDocumentReference.ParseSBOMFile`  | `ISbomReaderForExternalDocumentReference.ParseSbomFile`
`ISbomRedactor.RedactSBOMAsync` | `ISbomRedactor.RedactSbomAsync`
`ManifestInfo.ToSBOMSpecification` | `ManifestInfo.ToSbomSpecification`
`SbomConfigProvider.GetSBOMNamespaceUri` | `SbomConfigProvider.GetSbomNamespaceUri`
`SbomGenerator.GetSupportedSBOMSpecifications` | `SbomGenerator.GetSupportedSbomSpecifications`
`SbomRedactor.RedactSBOMAsync` | `SbomRedactor.RedactSbomAsync`
`SPDXSBOMReaderForExternalDocumentReference.ParseSBOMFile` | `SPDXSbomReaderForExternalDocumentReference.ParseSbomFile`
`TelemetryRecorder.RecordSBOMFormat` | `TelemetryRecorder.RecordSbomFormat`
`ValidatedSBOMFactory.CreateValidatedSBOM` | `ValidatedSbomFactory.CreateValidatedSbom`

### Properties and const values

Old name (all caps) | New name (Pascal case)
--- | ---
`Events.SBOMGenerationWorkflow` | `Events.SbomGenerationWorkflow`
`Events.SBOMParseMetadata` | `Events.SbomParseMetadata`
`Events.SBOMValidationWorkflow` | `Events.SbomValidationWorkflow`
`FileHashes.SBOMFileHash` | `FileHashes.SbomFileHash`
`IAssemblyConfig.DefaultSBOMNamespaceBaseUri` | `IAssemblyConfig.DefaultSbomNamespaceBaseUri`
`MetadataKey.SBOMToolName` | `MetadataKey.SbomToolName`
`MetadataKey.SBOMToolVersion` | `MetadataKey.SbomToolVersion`
`SettingsSource.SBOMApi` | `SettingsSource.SbomApi`

We discussed making a similar change with "SPDX", but ultimately decided to leave "SPDX" as all caps when dealing with interfaces and classes. There are many places in the code where variables use either camel casing or Pascal casing, but none of those should impact code that builds upon our API.

## Functional changes

If you use the Workflows that are documented [here](sbom-tool-cli-reference.md), then you will not be impacted by most of the functional changes. You will get the default implementations of the classes, which implement the current API. If, however, you create your own implementations or wrappers based on any of the interfaces exposed in our API, then you may need to make corresponding changes in your code. This table summarizes the changes:

Scope | Type of change | Detail
--- | --- | ---
`ILicenseInformationFetcher.FetchLicenseInformationAsync` | New parameter | `int timeoutInSeconds`
`ILicenseInformationFetcher.AppendLicensesToDictionary` | Generic Type | `IDictionary` instead of `Dictionary` for `partialLicenseDictionary`
`ILicenseInformationFetcher.ConvertClearlyDefinedApiResposeToList` | Generic Type | Returns `IDictionary` instead of `Dictionary`
`ILicenseInformationFetcher.ConvertComponentsToListForApi` | Generic Type | Returns `IList` instead of `List`
`ILicenseInformationFetcher.FetchLicenseInformationAsync` | Generic Type | Returns `IList` instead of `List`
`ILicenseInformationService.FetchLicenseInformationFromAPI` | New parameter | `int timeoutInSeconds`
`ILicenseInformationService.FetchLicenseInformationFromAPI` | Generic Type | `IList` instead of `List` for `listofComponetsForApi`
`ILicenseInformationService.FetchLicenseInformationFromAPI` | Generic Type | Returns `IList` instead of `List`
`IRecorder` | New method |  `void AddResult(string propertyName, string propertyValue)`
`IAssemblyConfig` | New property | `ManifestInfo DefaultManifestInfoForGenerationAction` 
`IJsonArrayGenerator.GenerateAsync` | Generic Type | `IList` instead of `List` for `listOfComponenentsForApi`
`IJsonArrayGenerator.GenerateAsync` | Generic Type | Returns `IList` instead of `List`
`IMetadataBuilder` | New method | `TryGetCreationInfoJson(IInternalMetadataProvider internalMetadataProvider, out GeneratorResult generatorResult)`
`IManifestToolJsonSerializer` | New method | `void Write(JsonElement jsonElement)`
`ISignedValidator.Validate` | New parameter | `IDictionary<string, string> additionalTelemetry`
`ISbomParser.GetMetadata()` | Return type | `SpdxMetadata` instead of `Spdx22Metadata`
`ISbomParser` | New method | `void EnforceConformanceStandard(ConformanceStandardType conformanceStandard)`
`IConfiguration` | New property | `ConfigurationSetting<ConformanceStandardType> ConformanceStandard`
`IConfiguration` | New property | `ConfigurationSetting<int> LicenseInformationTimeoutInSeconds`



