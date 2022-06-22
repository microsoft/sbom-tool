// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using System;
using Microsoft.Sbom.Common.Config.Attributes;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Common;
using Microsoft.Sbom.Common.Config.Validators;
using Microsoft.Sbom.Api.Utils;

namespace Microsoft.Sbom.Api.Config.Validators
{
    /// <summary>
    /// Verify that the directory path is writable.
    /// </summary>
    public class DirectoryPathIsWritableValidator : ConfigValidator
    {
        private readonly IFileSystemUtils fileSystemUtils;

        public DirectoryPathIsWritableValidator(IFileSystemUtils fileSystemUtils, IAssemblyConfig assemblyConfig)
            : base(typeof(DirectoryPathIsWritableAttribute), assemblyConfig)
        {
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        public override void ValidateInternal(string paramName, object paramValue, Attribute attribute)
        {
            if (paramValue != null && paramValue is string value && !string.IsNullOrEmpty(value))
            {
                // check if directory exist 
                if (!fileSystemUtils.DirectoryExists(value))
                {
                    throw new ValidationArgException($"{paramName} directory not found for '{value}'");
                }

                // check directory for write permission
                if (!fileSystemUtils.DirectoryHasWritePermissions(value))
                {
                    throw new AccessDeniedValidationArgException($"{paramName} directory does not have write permissions '{value}'");
                }
            }
        }
    }
}
