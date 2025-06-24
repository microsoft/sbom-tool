// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Sbom.Common;

namespace Microsoft.Sbom.Api.Config;

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

        var content = await fileSystemUtils.ReadAllTextAsync(filePath);
        if (string.IsNullOrEmpty(content))
        {
            return new ConfigFile();
        }

        var expandedContent = ExpandEnvironmentVariablesInString(content);
        return JsonSerializer.Deserialize<ConfigFile>(expandedContent);
    }

    private static string ExpandEnvironmentVariablesInString(string content)
    {
        var pattern = @"\$\(([^)]+)\)";
        return Regex.Replace(content, pattern, match =>
        {
            var envVarName = match.Groups[1].Value;
            var envVarValue = Environment.GetEnvironmentVariable(envVarName);

            return envVarValue;
        });
    }
}
