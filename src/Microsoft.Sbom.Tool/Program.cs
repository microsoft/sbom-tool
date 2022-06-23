// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using PowerArgs;
using Serilog;
using System;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Config;

namespace Microsoft.Sbom.Tool
{
    internal class Program
    {
        internal static string Name => NameValue.Value;

        internal static string Version => VersionValue.Value;

        private static readonly Lazy<string> NameValue = new Lazy<string>(() =>
        {
            return typeof(Program).GetTypeInfo().Assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product ?? "sbomtool";
        });

        private static readonly Lazy<string> VersionValue = new Lazy<string>(() =>
        {
            return typeof(Program).GetTypeInfo().Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty;
        });

        public static async Task<int> Main(string[] args)
        {
            var result = await Args.InvokeActionAsync<ManifestToolCmdRunner>(args);
            Log.CloseAndFlush();
            if (result.Cancelled || result.HandledException != null || result.Args.IsFailed)
            {
                if (result.Args != null && result.Args.IsAccessError)
                {
                    return (int)ExitCode.WriteAccessError;
                }

                return (int)ExitCode.GeneralError;
            }
            
            return (int)ExitCode.Success;
        }
    }
}
