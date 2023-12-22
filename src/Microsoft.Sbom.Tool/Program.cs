// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Tool;

using System;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.ComponentDetection.Orchestrator;
using Microsoft.ComponentDetection.Orchestrator.Commands;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Api.Config;
using Microsoft.Sbom.Api.Config.Args;
using Microsoft.Sbom.Api.Config.Extensions;
using Microsoft.Sbom.Api.Exceptions;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Extensions.DependencyInjection;
using PowerArgs;
using Serilog;
using Serilog.Events;
using Serilog.Filters;

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

    public static async Task Main(string[] args)
    {
        var result = await Args.InvokeActionAsync<SbomToolCmdRunner>(args);
        if (result.HandledException != null || (result.ActionArgs is not CommonArgs))
        {
            return;
        }

        try
        {
            await Host.CreateDefaultBuilder(args)
                .ConfigureServices((host, services) =>
                {
                    services = result.ActionArgs switch
                    {
                        ValidationArgs v => services.AddHostedService<ValidationService>(),
                        GenerationArgs g => services.AddHostedService<GenerationService>(),
                        _ => services
                    };

                    services
                        .AddTransient<ConfigFileParser>()
                        .AddSingleton(typeof(IConfigurationBuilder<>), typeof(ConfigurationBuilder<>))
                        .AddSingleton<IConfiguration>(provider =>
                        {
                            var validationConfigurationBuilder = provider.GetService<IConfigurationBuilder<ValidationArgs>>();
                            var generationConfigurationBuilder = provider.GetService<IConfigurationBuilder<GenerationArgs>>();
                            var inputConfiguration = result.ActionArgs switch
                            {
                                ValidationArgs v => validationConfigurationBuilder.GetConfiguration(v).GetAwaiter().GetResult(),
                                GenerationArgs g => generationConfigurationBuilder.GetConfiguration(g).GetAwaiter().GetResult(),
                                _ => default
                            };

                            inputConfiguration?.ToConfiguration();
                            return inputConfiguration; // Return the fetched input configuration
                        })

                        .AddSbomTool()
                        .AddLogging(l => l.ClearProviders()
                            .AddSerilog(new LoggerConfiguration()
                            .MinimumLevel.ControlledBy(Interceptor.LogLevel)
                            .Filter.ByExcluding(Matching.WithProperty("Microsoft.ComponentDetection.Orchestrator.Services.DetectorProcessingService"))
                            .Filter.ByExcluding(Matching.WithProperty("System.Net.Http.HttpClient"))
                            .Enrich.With<LoggingEnricher>()
                            .Enrich.FromLogContext()
                            .WriteTo.Map(
                                LoggingEnricher.LogFilePathPropertyName,
                                (logFilePath, wt) => wt.Async(x => x.File($"{logFilePath}")),
                                1) // sinkMapCountLimit
                            .WriteTo.Map<bool>(
                                LoggingEnricher.PrintStderrPropertyName,
                                (printLogsToStderr, wt) => wt.Logger(lc => lc
                                    .WriteTo.Console(outputTemplate: Constants.LoggerTemplate, standardErrorFromLevel: printLogsToStderr ? LogEventLevel.Debug : null)

                                    // Don't write the detection times table from DetectorProcessingService to the console, only the log file
                                    .Filter.ByExcluding(Matching.WithProperty<string>("DetectionTimeLine", x => !string.IsNullOrEmpty(x))))
                                    .Filter.ByExcluding(Matching.WithProperty<string>("System.Net.Http.HttpClient", x => !string.IsNullOrEmpty(x)))
                                    .Filter.ByExcluding(Matching.FromSource("Microsoft.ComponentDetection.Orchestrator.Services.DetectorProcessingService")),
                                1) // sinkMapCountLimit
                            .CreateLogger()));
                })
                .RunConsoleAsync(x => x.SuppressStatusMessages = true);
        }
        catch (AccessDeniedValidationArgException e)
        {
            Console.WriteLine(e.Message);
            Environment.ExitCode = (int)ExitCode.WriteAccessError;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e.Message);
            Environment.ExitCode = (int)ExitCode.GeneralError;
        }
    }
}
