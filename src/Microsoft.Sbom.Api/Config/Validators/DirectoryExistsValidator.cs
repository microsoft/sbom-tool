// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using PowerArgs;

namespace Microsoft.Sbom.Api.Config.Validators;

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
                if (fileSystemUtils.FileExists(value))
                {
                    throw new ValidationArgException($"{paramName} '{value}' must be a directory, not a file");
                }

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
