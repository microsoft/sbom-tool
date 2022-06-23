// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Contracts.Enums;
using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// FileTypeUtils is used to get the FileType for a given filename.
    /// </summary>
    public class FileTypeUtils : IFileTypeUtils
    {
        public List<FileType> GetFileTypesBy(string fileName)
        {
            if (!string.IsNullOrWhiteSpace(fileName) && fileName.EndsWith(Constants.SPDXFileExtension, StringComparison.OrdinalIgnoreCase))
            {
                return new List<FileType> { FileType.SPDX };
            }

            return null;
        }
    }
}
