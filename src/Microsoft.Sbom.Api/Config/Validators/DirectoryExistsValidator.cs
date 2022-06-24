﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Api.Utils;

namespace Microsoft.Sbom.Api.Config.Validators
{
    /// <summary>
    /// Validates if the directory exists with read permissions.
    /// </summary>
    public class DirectoryExistsValidator : ConfigValidator
    {
        private readonly IFileSystemUtils fileSystemUtils;

        public DirectoryExistsValidator(IFileSystemUtils fileSystemUtils, IAssemblyConfig assemblyConfig)
            : base(typeof(DirectoryExistsAttribute), assemblyConfig)
        {
            this.fileSystemUtils = fileSystemUtils;
        }

        public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
        {
            if (attribute is DirectoryExistsAttribute directoryExistsAttribute
                && directoryExistsAttribute.ForAction.HasFlag(CurrentAction))
            {
                if (paramValue != null
                    && paramValue is string value
                    && !string.IsNullOrEmpty(value))
                {
                    if (!fileSystemUtils.DirectoryExists(value))
                    {
                        throw new ValidationArgException($"{paramName} directory not found for '{value}'");
                    }

                    if (directoryExistsAttribute.HasReadPermissions && !fileSystemUtils.DirectoryHasReadPermissions(value))
                    {
                        throw new ValidationArgException($"{paramName} directory does not have read permissions '{value}'");
                    }

                    if (directoryExistsAttribute.HasWritePermissions && !fileSystemUtils.DirectoryHasWritePermissions(value))
                    {
                        throw new ValidationArgException($"{paramName} directory does not have write permissions '{value}'");
                    }
                }
            }
        }
    }
}
