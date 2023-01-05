// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Api.Metadata;
using Microsoft.Sbom.Api.Output.Telemetry;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Sbom.Api.Manifest.Configuration
{
    /// <summary>
    /// Provides a list of configs for all the SBOM formats that need to be generated.
    /// We might need to generate more than one SBOM for backward compatibility.
    /// </summary>
    public class SbomConfigProvider : ISbomConfigProvider
    {
        private readonly IDictionary<ManifestInfo, ISbomConfig> configsDictionary = new Dictionary<ManifestInfo, ISbomConfig>();
        private readonly IEnumerable<IMetadataProvider> metadataProviders;
        private readonly ILogger logger;
        private readonly IReadOnlyDictionary<MetadataKey, object> metadataDictionary;

        public SbomConfigProvider(
            IEnumerable<IManifestConfigHandler> manifestConfigHandlers,
            IEnumerable<IMetadataProvider> metadataProviders,
            ILogger logger,
            IRecorder recorder)
        {
            if (manifestConfigHandlers is null)
            {
                throw new ArgumentNullException(nameof(manifestConfigHandlers));
            }

            foreach (var configHandler in manifestConfigHandlers)
            {
                if (configHandler.TryGetManifestConfig(out ISbomConfig sbomConfig))
                {
                    configsDictionary.Add(sbomConfig.ManifestInfo, sbomConfig);
                    recorder.RecordSBOMFormat(sbomConfig.ManifestInfo, sbomConfig.ManifestJsonFilePath);
                }
            }

            this.metadataProviders = metadataProviders ?? throw new ArgumentNullException(nameof(metadataProviders));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));

            metadataDictionary = InitializeDictionary();
        }

        /// <inheritdoc/>
        public ISbomConfig Get(ManifestInfo manifestInfo)
        {
            if (manifestInfo is null)
            {
                throw new ArgumentNullException(nameof(manifestInfo));
            }

            return configsDictionary[manifestInfo];
        }

        /// <inheritdoc/>
        public bool TryGet(ManifestInfo manifestInfo, out ISbomConfig sbomConfig)
        {
            if (manifestInfo is null)
            {
                throw new ArgumentNullException(nameof(manifestInfo));
            }

            return configsDictionary.TryGetValue(manifestInfo, out sbomConfig);
        }

        public IEnumerable<ManifestInfo> GetManifestInfos()
        {
            return configsDictionary.Keys;
        }

        public IDisposable StartJsonSerialization()
        {
            ApplyToEachConfig(c => c.StartJsonSerialization());
            return this;
        }

        public IAsyncDisposable StartJsonSerializationAsync()
        {
            ApplyToEachConfig(c => c.StartJsonSerialization());
            return this;
        }

        /// <summary>
        /// Helper method to operate an action on each included configs.
        /// </summary>
        /// <param name="action">The action to perform on the config.</param>
        public void ApplyToEachConfig(Action<ISbomConfig> action)
        {
            foreach (var config in configsDictionary)
            {
                action(config.Value);
            }
        }

        #region IInternalMetadataProvider implementation

        private IReadOnlyDictionary<MetadataKey, object> InitializeDictionary()
        {
            try
            {
                return metadataProviders
                    .Select(md => md.MetadataDictionary)
                    .SelectMany(dict => dict)
                    .Where(kvp => kvp.Value != null)
                    .GroupBy(kvp => kvp.Key, kvp => kvp.Value)
                    .ToDictionary(g => g.Key, g => g.First());
            }
            catch (ArgumentException e)
            {
                // Sanitize exceptions.
                throw new Exception($"An error occured while creating metadata entries for the SBOM.", e);
            }
        }

        public object GetMetadata(MetadataKey key)
        {
            if (metadataDictionary.TryGetValue(key, out object value))
            {
                logger.Debug($"Found value for header {key} in internal metadata.");
                return value;
            }

            throw new Exception($"Value for header {key} not found in internal metadata");
        }

        public bool TryGetMetadata(MetadataKey key, out object value)
        {
            if (metadataDictionary.ContainsKey(key))
            {
                logger.Debug($"Found value for header {key} in internal metadata.");
                value = metadataDictionary[key];
                return true;
            }

            value = null;
            return false;
        }

        public GenerationData GetGenerationData(ManifestInfo manifestInfo)
        {
            if (configsDictionary.TryGetValue(manifestInfo, out ISbomConfig sbomConfig))
            {
                return sbomConfig.Recorder.GetGenerationData();
            }

            throw new Exception($"Unable to get generation data for the {manifestInfo} SBOM.");
        }

        public string GetSBOMNamespaceUri()
        {
            IMetadataProvider provider = null;
            if (metadataDictionary.TryGetValue(MetadataKey.BuildEnvironmentName, out object buildEnvironmentName))
            {
                provider = metadataProviders
                    .Where(p => p.BuildEnvironmentName != null && p.BuildEnvironmentName == buildEnvironmentName as string)
                    .FirstOrDefault();
            }
            else
            {
                provider = metadataProviders.FirstOrDefault(p => p is IDefaultMetadataProvider);
            }

            if (provider != null)
            {
                return provider.GetDocumentNamespaceUri();
            }

            logger.Error($"Unable to find any provider to generate the namespace.");
            throw new Exception($"Unable to find any provider to generate the namespace.");
        }

        #endregion

        #region Disposable implementation

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public async ValueTask DisposeAsync()
        {
            await DisposeAsyncCore();

            Dispose(disposing: false);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                ApplyToEachConfig(c => c.Dispose());
            }
        }

        protected virtual async ValueTask DisposeAsyncCore()
        {
            foreach (var config in configsDictionary)
            {
                await config.Value.DisposeAsync().ConfigureAwait(false);
            }
        }

        #endregion
    }
}
