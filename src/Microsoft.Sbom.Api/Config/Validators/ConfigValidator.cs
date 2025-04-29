// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Extensions.Entities;

namespace Microsoft.Sbom.Common.Config.Validators;

/// <summary>
/// Abstract class from which all validators must inherit.
/// This class only validates configuration properties that are of the type <see cref="ConfigurationSetting{T}"/>.
/// </summary>
public abstract class ConfigValidator
{
    private readonly IAssemblyConfig assemblyConfig;

    /// <summary>
    /// This is the attribute that a property must have in order to be validated by this validator.
    /// </summary>
    private readonly Type supportedAttribute;

    /// <summary>
    /// Gets or sets the current action being performed on the manifest tool.
    /// </summary>
    public ManifestToolActions CurrentAction { get; set; }

    protected ConfigValidator(Type supportedAttribute, IAssemblyConfig assemblyConfig)
    {
        this.supportedAttribute = supportedAttribute ?? throw new ArgumentNullException(nameof(supportedAttribute));
        this.assemblyConfig = assemblyConfig ?? throw new ArgumentNullException(nameof(assemblyConfig));
    }

    /// <summary>
    /// Validates a given property, throws a <see cref="PowerArgs.ValidationArgException"/> if validation fails.
    /// </summary>
    /// <param name="propertyName">The name of the property.</param>
    /// <param name="propertyValue">The <see cref="ConfigurationSetting{T}"/> value of the property.</param>
    /// <param name="attributeCollection">The attributes assigned to this property.</param>
    public void Validate(string propertyName, object propertyValue, AttributeCollection attributeCollection)
    {
        if (string.IsNullOrEmpty(propertyName))
        {
            throw new ArgumentException($"'{nameof(propertyName)}' cannot be null or empty", nameof(propertyName));
        }

        var attribute = attributeCollection[supportedAttribute];
        if (attribute == null)
        {
            return;
        }

        // Skip validation of the NamespaceUriBase if it is empty or has a default provided by the assembly info, This case is handled in the ConfigSanitizer.
        if (propertyName == nameof(IConfiguration.NamespaceUriBase) && NamespaceUriBaseIsNullOrHasDefaultValue(propertyValue))
        {
            return;
        }

        if (propertyName == nameof(IConfiguration.PackageSupplier) && !string.IsNullOrEmpty(assemblyConfig.DefaultPackageSupplier))
        {
            return;
        }

        // Skip validation of (-b) when it is null, validation for this scenario will happen in the ConfigSanitizer.
        if (propertyName == nameof(IConfiguration.BuildDropPath) && propertyValue == null)
        {
            return;
        }

        if (propertyName == nameof(IConfiguration.FailIfNoPackages))
        {
            return;
        }

        // Skip validation of the Conformance. This case is handled in the ConfigSanitizer.
        if (propertyName == nameof(IConfiguration.ConformanceStandard))
        {
            return;
        }

        switch (propertyValue)
        {
            case null:
                // If the value is null, let the implementing validator handle it.
                ValidateInternal(propertyName, propertyValue, attribute);
                break;

            case ConfigurationSetting<object> configSetting:
                ValidateInternal(propertyName, configSetting.Value, attribute);
                break;

            case ConfigurationSetting<int> configSettingInt:
                ValidateInternal(propertyName, configSettingInt.Value, attribute);
                break;

            case ConfigurationSetting<string> configSettingString:
                ValidateInternal(propertyName, configSettingString.Value, attribute);
                break;

            case ConfigurationSetting<IList<ManifestInfo>> configSettingList:
                ValidateInternal(propertyName, configSettingList.Value, attribute);
                break;

            default:
                throw new ArgumentException($"'{propertyName}' must be of type '{typeof(ConfigurationSetting<>)}'");
        }
    }

    private bool NamespaceUriBaseIsNullOrHasDefaultValue(object propertyValue)
    {
        var defaultProperty = assemblyConfig.DefaultSbomNamespaceBaseUri;

        if (propertyValue == null || !string.IsNullOrEmpty(defaultProperty))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    public abstract void ValidateInternal(string paramName, object paramValue, Attribute attribute);
}
