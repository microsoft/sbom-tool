// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualBasic;
using System;
using System.ComponentModel;
using System.IO;

namespace Microsoft.Sbom.Common.Config.Validators
{
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

            Attribute attribute = attributeCollection[supportedAttribute];
            if (attribute == null)
            {
                return;
            }

            // If default value for namespace base uri is provided in the assembly info, skip value check requirements.
            if (propertyName == nameof(IConfiguration.NamespaceUriBase) && !string.IsNullOrEmpty(assemblyConfig.DefaultSBOMNamespaceBaseUri))
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

                default:
                    throw new ArgumentException($"'{propertyName}' must be of type '{typeof(ConfigurationSetting<>)}'");
            }
        }

        public abstract void ValidateInternal(string paramName, object paramValue, Attribute attribute);
    }
}
