// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Common.Config.Attributes;
using System;
using System.IO;
using System.Reflection;
using System.Linq;

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

        private static readonly Lazy<string> DefaultSBOMBaseNamespaceUri
            = GetCustomAttributeValue<DefaultNamespaceBaseUriAttribute, string>(a => a?.DefaultBaseNamespaceUri);

        private static readonly Lazy<string> DefaultSBOMBaseNamespaceUriWarningMessage
            = GetCustomAttributeValue<DefaultNamespaceBaseUriAttribute, string>(a => a?.WarningMessage);

        private static readonly Lazy<ManifestInfo> DefaultManifestInfoForValidationActionValue
            = GetCustomAttributeValue<DefaultManifestInfoArgForValidationAttribute, ManifestInfo>(a => a?.ManifestInfo);

        private static readonly Lazy<string> AssemblyDirectoryValue = new Lazy<string>(() =>
        {
            string location = Assembly.GetExecutingAssembly().Location;
            return Path.GetDirectoryName(location);
        });

        private static Lazy<TVal> GetCustomAttributeValue<T, TVal>(Func<T, TVal> getValue)
            where T : Attribute
            => new Lazy<TVal>(() =>
            {
                var attr = AppDomain.CurrentDomain
                    .GetAssemblies()
                    .FirstOrDefault(a => a.IsDefined(typeof(T)))?.GetCustomAttribute<T>();
                return getValue(attr);
            });
    }
}
