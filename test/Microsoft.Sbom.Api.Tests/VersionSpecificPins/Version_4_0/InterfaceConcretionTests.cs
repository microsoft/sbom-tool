// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Orchestrator.Commands;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Convertors;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Executors;
using Microsoft.Sbom.Api.Filters;
using Microsoft.Sbom.Api.FormatValidator;
using Microsoft.Sbom.Api.Hashing;
using Microsoft.Sbom.Api.Manifest;
using Microsoft.Sbom.Api.Output;
using Microsoft.Sbom.Api.Output.Telemetry;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.Sbom.Api.Providers;
using Microsoft.Sbom.Api.SignValidator;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Api.Workflows;
using Microsoft.Sbom.Api.Workflows.Helpers;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.JsonAsynchronousNodeKit;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Serilog.Events;

namespace Microsoft.Sbom.Api.Tests.VersionSpecificPins.Version_4_0;

/// <summary>
/// Test class to pin concrete implementations of interfaces. If this class (or any of its private classes) fails to
/// compile, it means that the interface has changed and we require a major version bump.
/// </summary>
[TestClass]
public class InterfaceConcretionTests
{
    [TestMethod]
    public void Future_CheckDependentTypes()
    {
        // TODO: Use reflection to ensure that our tyes haven't broken by any changes.
        // For now, just let the test pass.
    }

#pragma warning disable SA1516 // Skip blank line between elements in the concrete implementations

    private class PinnedIConfigurationBuilder : IConfigurationBuilder<string>
    {
        public Task<InputConfiguration> GetConfiguration(string args) => throw new NotImplementedException();
    }

    private class PinnedISbomSevice : ISbomService<CommonArgs>
    {
    }

    private class PinnedIManifestPathConverter : IManifestPathConverter
    {
        public (string, bool) Convert(string path, bool prependDotToPath) => throw new NotImplementedException();
    }

    private class PinnedILicenseInformationFetcher : ILicenseInformationFetcher
    {
        public void AppendLicensesToDictionary(Dictionary<string, string> partialLicenseDictionary) => throw new NotImplementedException();
        public Dictionary<string, string> ConvertClearlyDefinedApiResponseToList(string httpResponseContent) => throw new NotImplementedException();
        public List<string> ConvertComponentsToListForApi(IEnumerable<ScannedComponent> scannedComponents) => throw new NotImplementedException();
        public Task<List<string>> FetchLicenseInformationAsync(List<string> listOfComponentsForApi, int timeoutInSeconds) => throw new NotImplementedException();
        public string GetFromLicenseDictionary(string key) => throw new NotImplementedException();
        public ConcurrentDictionary<string, string> GetLicenseDictionary() => throw new NotImplementedException();
    }

    private class PinnedILicenstInformationService : ILicenseInformationService
    {
        public Task<List<string>> FetchLicenseInformationFromAPI(List<string> listOfComponentsForApi, int timeoutInSeconds) => throw new NotImplementedException();
    }

    private class Pinned_SBOMReaderForExternalDocumentReference : ISbomReaderForExternalDocumentReference
    {
        public (ChannelReader<ExternalDocumentReferenceInfo> results, ChannelReader<FileValidationResult> errors) ParseSbomFile(ChannelReader<string> sbomFileLocation) => throw new NotImplementedException();
    }

    private class PinnedIFilter : IFilter<PinnedIFilter>
    {
        public void Init() => throw new NotImplementedException();
        public bool IsValid(string filePath) => throw new NotImplementedException();
    }

    private class PinnedIValidatedSBOM : IValidatedSbom
    {
        public void Dispose() => throw new NotImplementedException();
        public Task<FormatEnforcedSPDX2> GetRawSPDXDocument() => throw new NotImplementedException();
        public Task<FormatValidationResults> GetValidationResults() => throw new NotImplementedException();
    }

    private class PinnedIHashAlgorithmProvider : IHashAlgorithmProvider
    {
        public AlgorithmName Get(string algorithmName) => throw new NotImplementedException();
    }

    private class PinnedIHashCodeGenerator : IHashCodeGenerator
    {
        public Contracts.Checksum[] GenerateHashes(string filePath, AlgorithmName[] hashAlgorithmNames) => throw new NotImplementedException();
    }

    private class PinnedIManifestParserProvider : IManifestParserProvider
    {
        public IManifestInterface Get(ManifestInfo manifestInfo) => throw new NotImplementedException();
        public void Init() => throw new NotImplementedException();
    }

    private class PinnedIOutputWriter : IOutputWriter
    {
        public Task WriteAsync(string output) => throw new NotImplementedException();
    }

    private class PinnedIRecorder : IRecorder
    {
        public IList<FileValidationResult> Errors => throw new NotImplementedException();

        public void AddResult(string propertyName, string value) => throw new NotImplementedException();
        public void AddToTotalCountOfLicenses(int count) => throw new NotImplementedException();
        public void AddToTotalNumberOfPackageDetailsEntries(int count) => throw new NotImplementedException();
        public Task FinalizeAndLogTelemetryAsync() => throw new NotImplementedException();
        public void RecordAPIException(Exception exception) => throw new NotImplementedException();
        public void RecordException(Exception exception) => throw new NotImplementedException();
        public void RecordMetadataException(Exception exception) => throw new NotImplementedException();
        public void RecordSbomFormat(ManifestInfo manifestInfo, string sbomFilePath) => throw new NotImplementedException();
        public void RecordSwitch(string switchName, object value) => throw new NotImplementedException();
        public void RecordTotalErrors(IList<FileValidationResult> errors) => throw new NotImplementedException();
        public void RecordTotalNumberOfPackages(int count) => throw new NotImplementedException();
        public TimingRecorder TraceEvent(string eventName) => throw new NotImplementedException();
    }

    private class PinnedIPackageManagerUtils : IPackageManagerUtils<PinnedIPackageManagerUtils>
    {
        public string GetMetadataLocation(ScannedComponent scannedComponent) => throw new NotImplementedException();
        public ParsedPackageInformation ParseMetadata(string pomLocation) => throw new NotImplementedException();
    }

    private class PinnedIPackageDetailsFactory : IPackageDetailsFactory
    {
        public IDictionary<(string Name, string Version), Api.PackageDetails.PackageDetails> GetPackageDetailsDictionary(IEnumerable<ScannedComponent> scannedComponents) => throw new NotImplementedException();
    }

    private class PinnedISourcesProvider : ISourcesProvider
    {
        public (ChannelReader<JsonDocWithSerializer> results, ChannelReader<FileValidationResult> errors) Get(IList<ISbomConfig> requiredConfigs) => throw new NotImplementedException();
        public bool IsSupported(ProviderType providerType) => throw new NotImplementedException();
    }

    private class PinnedISignValidationProvider : ISignValidationProvider
    {
        public ISignValidator Get() => throw new NotImplementedException();
        public void Init() => throw new NotImplementedException();
    }

    private class PinnedIAssemblyConfig : IAssemblyConfig
    {
        public string DefaultSbomNamespaceBaseUri => throw new NotImplementedException();

        public ManifestInfo DefaultManifestInfoForValidationAction => throw new NotImplementedException();

        public ManifestInfo DefaultManifestInfoForGenerationAction => throw new NotImplementedException();

        public string AssemblyDirectory => throw new NotImplementedException();

        public string DefaultPackageSupplier => throw new NotImplementedException();
    }

    private class PinnedIComponentDetector : IComponentDetector
    {
        public Task<ScanResult> ScanAsync(ScanSettings args) => throw new NotImplementedException();
    }

    private class PinnedIFileTypeUtils : IFileTypeUtils
    {
        public List<FileType> GetFileTypesBy(string fileName) => throw new NotImplementedException();
    }

    private class PinnedIJsonArrayGenerator : IJsonArrayGenerator<PinnedIJsonArrayGenerator>
    {
        public ISbomConfig SbomConfig { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string SpdxManifestVersion { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public Task<IList<FileValidationResult>> GenerateAsync() => throw new NotImplementedException();
        Task<Api.Workflows.Helpers.GenerationResult> IJsonArrayGenerator<PinnedIJsonArrayGenerator>.GenerateAsync() => throw new NotImplementedException();
    }

    private class PinnedISbomRedactor : ISbomRedactor
    {
        public Task<FormatEnforcedSPDX2> RedactSbomAsync(IValidatedSbom sbom) => throw new NotImplementedException();
    }

    private class PinnedIWorkflow : IWorkflow<PinnedIWorkflow>
    {
        public Task<bool> RunAsync() => throw new NotImplementedException();
    }

    private class PinnedIManifestInterface : IManifestInterface
    {
        public string Version { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public ISbomParser CreateParser(Stream stream) => throw new NotImplementedException();
        public ManifestData ParseManifest(string manifest) => throw new NotImplementedException();
        public ManifestInfo[] RegisterManifest() => throw new NotImplementedException();
    }

    private class PinnedISbomConfig : ISbomConfig
    {
        public string ManifestJsonDirPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string ManifestJsonFilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string ManifestJsonFileSha256FilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string CatalogFilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string BsiFilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ManifestInfo ManifestInfo { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public IMetadataBuilder MetadataBuilder { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public IManifestToolJsonSerializer JsonSerializer => throw new NotImplementedException();

        public ISbomPackageDetailsRecorder Recorder { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public void Dispose() => throw new NotImplementedException();
        public ValueTask DisposeAsync() => throw new NotImplementedException();
        public void StartJsonSerialization() => throw new NotImplementedException();
    }

    private class PinnedIMetadataBuilder : IMetadataBuilder
    {
        public string GetHeaderJsonString(IInternalMetadataProvider internalMetadataProvider) => throw new NotImplementedException();
        public bool TryGetCreationInfoJson(IInternalMetadataProvider internalMetadataProvider, out Extensions.Entities.GenerationResult generationResult) => throw new NotImplementedException();
        public bool TryGetExternalRefArrayHeaderName(out string headerName) => throw new NotImplementedException();
        public bool TryGetFilesArrayHeaderName(out string headerName) => throw new NotImplementedException();
        public bool TryGetPackageArrayHeaderName(out string headerName) => throw new NotImplementedException();
        public bool TryGetRelationshipsHeaderName(out string headerName) => throw new NotImplementedException();
        public bool TryGetRootPackageJson(IInternalMetadataProvider internalMetadataProvider, out Extensions.Entities.GenerationResult generationResult) => throw new NotImplementedException();
    }

    private class PinnedIManifestToolJsonSerializer : IManifestToolJsonSerializer
    {
        public void Dispose() => throw new NotImplementedException();
        public ValueTask DisposeAsync() => throw new NotImplementedException();
        public void EndJsonArray() => throw new NotImplementedException();
        public void FinalizeJsonObject() => throw new NotImplementedException();
        public void StartJsonArray(string arrayHeader) => throw new NotImplementedException();
        public void StartJsonObject() => throw new NotImplementedException();
        public void Write(JsonDocument jsonDocument) => throw new NotImplementedException();
        public void Write(JsonElement jsonElement) => throw new NotImplementedException();
        public void WriteJsonString(string jsonString) => throw new NotImplementedException();
    }

    private class PinnedISbomPackageDetailsRecorder : ISbomPackageDetailsRecorder
    {
        public GenerationData GetGenerationData() => throw new NotImplementedException();
        public void RecordChecksumForFile(Contracts.Checksum[] checksums) => throw new NotImplementedException();
        public void RecordDocumentId(string documentId) => throw new NotImplementedException();
        public void RecordExternalDocumentReferenceIdAndRootElement(string externalDocumentReferenceId, string rootElement) => throw new NotImplementedException();
        public void RecordFileId(string fileId) => throw new NotImplementedException();
        public void RecordPackageId(string packageId, string dependOn) => throw new NotImplementedException();
        public void RecordRootPackageId(string rootPackageId) => throw new NotImplementedException();
        public void RecordSPDXFileId(string spdxFileId) => throw new NotImplementedException();
    }

    private class PinnedIInternalMetadataProvider : IInternalMetadataProvider
    {
        public GenerationData GetGenerationData(ManifestInfo manifestInfo) => throw new NotImplementedException();
        public object GetMetadata(MetadataKey key) => throw new NotImplementedException();
        public string GetSbomNamespaceUri() => throw new NotImplementedException();
        public bool TryGetMetadata(MetadataKey key, out object value) => throw new NotImplementedException();
        public bool TryGetMetadata(MetadataKey key, out string value) => throw new NotImplementedException();
    }

    private class PinnedISignValidator : ISignValidator
    {
        public OSPlatform SupportedPlatform => throw new NotImplementedException();
        public bool Validate(IDictionary<string, string> additionalTelemetry) => throw new NotImplementedException();
    }

    private class PinnedISbomParser : ISbomParser
    {
        public SpdxMetadata GetMetadata() => throw new NotImplementedException();
        public ParserStateResult Next() => throw new NotImplementedException();
        public ManifestInfo[] RegisterManifest() => throw new NotImplementedException();
        public void EnforceConformance(ConformanceType conformance) => throw new NotImplementedException();
    }

    private class PinnedIConfiguration : IConfiguration
    {
        public ConfigurationSetting<string> BuildDropPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> BuildComponentPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> BuildListFile { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> ManifestPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> ManifestDirPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> OutputPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<int> Parallelism { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<LogEventLevel> Verbosity { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> ConfigFilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<IList<ManifestInfo>> ManifestInfo { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<AlgorithmName> HashAlgorithm { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> RootPathFilter { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> CatalogFilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> ValidateSignature { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> IgnoreMissing { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ManifestToolActions ManifestToolAction { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> PackageName { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> PackageVersion { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> PackageSupplier { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<IEnumerable<SbomFile>> FilesList { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<IEnumerable<SbomPackage>> PackagesList { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> TelemetryFilePath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> DockerImagesToScan { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> ExternalDocumentReferenceListFile { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> AdditionalComponentDetectorArgs { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> NamespaceUriUniquePart { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> NamespaceUriBase { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> GenerationTimestamp { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> FollowSymlinks { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> DeleteManifestDirIfPresent { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> FailIfNoPackages { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> FetchLicenseInformation { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<bool> EnablePackageMetadataParsing { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> SbomPath { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<string> SbomDir { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<ConformanceType> Conformance { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ConfigurationSetting<int> LicenseInformationTimeoutInSeconds { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
    }

    private class PinnedISettingSourceable : ISettingSourceable
    {
        public SettingSource Source { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
    }

    // TODO: Data Types
    // AlgorithmName
    // Annotation
    // Checksum
    // ConfigurationSetting
    // Entity
    // EntityError
    // EntityType
    // ErrorType
    // ExternalDocumentReferenceInfo
    // ExternalReference
    // ExtractedLicensingInfo
    // FileType
    // FileValidationResult
    // FormatEnforcedSPDX2
    // FormatValidationResults
    // GenerationData
    // GenerationResult
    // InputConfiguration
    // JsonDocument
    // JsonDocWithSerializer
    // LicenseInfo
    // LogEventLevel
    // ManifestData
    // ManifestInfo
    // ManifestToolActions
    // MetadataKey
    // PackageDetails
    // PackageVerificationCode
    // ParsedPackageInformation
    // ParserStateResult
    // ProviderType
    // ResultMetadata
    // SbomFile
    // SbomPackage
    // ScannedComponent (CD)
    // ScanResult (CD)
    // ScanSettings (CD)
    // SettingSource
    // Snippet
    // SpdxMetadata
    // SPDXFile
    // SPDXPackage
    // SPDXRelationship
    // TimingRecorder

#pragma warning restore SA1516

}
