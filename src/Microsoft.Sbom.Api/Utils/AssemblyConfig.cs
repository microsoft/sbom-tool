// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Api.Utils;

/// <inheritdoc/>
public class AssemblyConfig : IAssemblyConfig
{
    /// <inheritdoc/>
    public string DefaultSbomNamespaceBaseUri => DefaultSbomBaseNamespaceUri.Value;

    /// <inheritdoc/>
    public ManifestInfo DefaultManifestInfoForValidationAction => DefaultManifestInfoForValidationActionValue.Value;

    /// <inheritdoc>
    public ManifestInfo DefaultManifestInfoForGenerationAction => DefaultManifestInfoForGenerationActionValue.Value;

    public string DefaultPackageSupplier => PackageSupplier.Value;

    /// <inheritdoc/>
    public string AssemblyDirectory => AssemblyDirectoryValue.Value;

    private static readonly Lazy<string> DefaultSbomBaseNamespaceUri
        = GetCustomAttributeValue<DefaultNamespaceBaseUriAttribute, string>(a => a?.DefaultBaseNamespaceUri);

    private static readonly Lazy<ManifestInfo> DefaultManifestInfoForValidationActionValue
        = GetCustomAttributeValue<DefaultManifestInfoArgForValidationAttribute, ManifestInfo>(a => a?.ManifestInfo);

    private static readonly Lazy<ManifestInfo> DefaultManifestInfoForGenerationActionValue
        = GetCustomAttributeValue<DefaultManifestInfoArgForGenerationAttribute, ManifestInfo>(a => a?.ManifestInfo);

    private static readonly Lazy<string> PackageSupplier = GetCustomAttributeValue<PackageSupplierAttribute, string>(a => a?.PackageSupplier);

    private static readonly Lazy<string> AssemblyDirectoryValue = new Lazy<string>(() =>
    {
        var location = Assembly.GetExecutingAssembly().Location;
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
