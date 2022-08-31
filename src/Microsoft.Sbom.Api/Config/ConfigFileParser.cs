// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Utils.FileSystem;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Config
{
    /// <summary>
    /// Used to parse the configuration as a <see cref="ConfigFile"/> from a JSON file.
    /// </summary>
    public class ConfigFileParser
    {
        private readonly IFileSystemUtils fileSystemUtils;

        public ConfigFileParser(IFileSystemUtils fileSystemUtils)
        {
            this.fileSystemUtils = fileSystemUtils ?? throw new ArgumentNullException(nameof(fileSystemUtils));
        }

        public async Task<ConfigFile> ParseFromJsonFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new ArgumentNullException($"{nameof(filePath)} cannot be emtpy.");
            }

            using Stream openStream = fileSystemUtils.OpenRead(filePath);
            return await JsonSerializer.DeserializeAsync<ConfigFile>(openStream);
        }
    }
}
