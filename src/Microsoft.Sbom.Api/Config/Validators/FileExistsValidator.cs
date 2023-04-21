// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Api.Utils;

namespace Microsoft.Sbom.Api.Config.Validators;

/// <summary>
/// Validates if the file exists.
/// </summary>
public class FileExistsValidator : ConfigValidator
{
    private readonly IFileSystemUtils fileSystemUtils;

    public FileExistsValidator(IFileSystemUtils fileSystemUtils, IAssemblyConfig assemblyConfig)
        : base(typeof(FileExistsAttribute), assemblyConfig)
    {
        this.fileSystemUtils = fileSystemUtils;
    }

    public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
    {
        if (paramValue != null && paramValue is string value && !string.IsNullOrEmpty(value))
        {
            if (!fileSystemUtils.FileExists(value))
            {
                throw new ValidationArgException($"{paramName} file not found for '{value}'");
            }
        }
    }
}