// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common.Config.Attributes;
using System;
using System.IO;
using System.Reflection;

namespace Microsoft.Sbom.Api.Utils
{
    /// <inheritdoc/>
    public class AssemblyConfig : IAssemblyConfig
    {
        /// <inheritdoc/>
        public string DefaultSBOMNamespaceBaseUri => DefaultSBOMBaseNamespaceUri.Value;

        /// <inheritdoc/>
        public string DefaultSBOMNamespaceBaseUriWarningMessage => DefaultSBOMBaseNamespaceUriWarningMessage.Value;

        /// <inheritdoc/>
        public ManifestInfo DefaultManifestInfoForValidationAction => DefaultManifestInfoForValidationActionValue.Value;

        /// <inheritdoc/>
        public string AssemblyDirectory => AssemblyDirectoryValue.Value;

        private static readonly Lazy<string> DefaultSBOMBaseNamespaceUri = new Lazy<string>(() =>
        {
            return Assembly.GetExecutingAssembly().GetCustomAttribute<DefaultNamespaceBaseUriAttribute>()?.DefaultBaseNamespaceUri;
        });

        private static readonly Lazy<string> DefaultSBOMBaseNamespaceUriWarningMessage = new Lazy<string>(() =>
        {
            return Assembly.GetExecutingAssembly().GetCustomAttribute<DefaultNamespaceBaseUriAttribute>()?.WarningMessage;
        });

        private static readonly Lazy<ManifestInfo> DefaultManifestInfoForValidationActionValue = new Lazy<ManifestInfo>(() =>
        {
            return Assembly.GetExecutingAssembly().GetCustomAttribute<DefaultManifestInfoArgForValidationAttribute>()?.ManifestInfo;
        });

        private static readonly Lazy<string> AssemblyDirectoryValue = new Lazy<string>(() =>
        {
            string location = Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(location);
        });
    }
}
