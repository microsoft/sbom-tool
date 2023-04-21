// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Api.Utils;

namespace Microsoft.Sbom.Api.Config.Validators;

/// <summary>
/// Verify that the filepath is writable.
/// </summary>
public class FilePathIsWritableValidator : ConfigValidator
{
    private readonly IFileSystemUtils fileSystemUtils;

    public FilePathIsWritableValidator(IFileSystemUtils fileSystemUtils, IAssemblyConfig assemblyConfig)
        : base(typeof(FilePathIsWritableAttribute), assemblyConfig)
    {
        this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
    }

    public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
    {
        if (paramValue != null && paramValue is string value && !string.IsNullOrEmpty(value))
        {
            string directoryPath;
            try
            {
                directoryPath = fileSystemUtils.GetDirectoryName(value);
            }
            catch (Exception e)
            {
                throw new ValidationArgException($"Unable to get directory for '{value}': {e.Message}");
            }

            // check if directory exist 
            if (!fileSystemUtils.DirectoryExists(directoryPath))
            {
                throw new ValidationArgException($"{paramName} directory not found for '{value}'");
            }

            // check directory for write permission
            if (!fileSystemUtils.DirectoryHasWritePermissions(directoryPath))
            {
                throw new ValidationArgException($"{paramName} directory does not have write permissions '{directoryPath}'");
            }
        }
    }
}