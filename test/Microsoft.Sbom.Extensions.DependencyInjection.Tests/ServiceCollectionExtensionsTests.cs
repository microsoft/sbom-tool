// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Serilog.Events;
using Spectre.Console;

namespace Microsoft.Sbom.Extensions.DependencyInjection.Tests;

// Regression coverage for https://github.com/dotnet/msbuild/issues/14691: AddSbomTool must
// register its own IAnsiConsole so ComponentDetection never falls back to the static, process-wide
// AnsiConsole.Console singleton, which lazily captures Console.Out and can outlive it under
// MSBuild Server reuse.
[TestClass]
[DoNotParallelize]
public class ServiceCollectionExtensionsTests
{
    [TestMethod]
    public void AddSbomTool_RegistersLocalAnsiConsole_DistinctFromProcessWideSingleton()
    {
        var services = new ServiceCollection();
        services.AddSbomTool(LogEventLevel.Fatal);
        using var provider = services.BuildServiceProvider();

        var resolved = provider.GetRequiredService<IAnsiConsole>();

        Assert.IsNotNull(resolved);
        Assert.AreNotSame(AnsiConsole.Console, resolved, "AddSbomTool must not rely on the process-wide AnsiConsole.Console singleton.");
    }

    [TestMethod]
    public void AddSbomTool_ResolvesIndependentAnsiConsole_AfterPriorConsoleOutIsDisposed()
    {
        var originalOut = Console.Out;
        IAnsiConsole firstInvocationConsole;
        IAnsiConsole secondInvocationConsole;

        try
        {
            // Build #1: bind Console.Out, resolve IAnsiConsole from a fresh DI container, write to
            // it, then dispose the writer -- mirroring MSBuild Server disposing its
            // RedirectConsoleWriter after the build completes.
            using (var firstInvocationWriter = new StringWriter())
            {
                Console.SetOut(firstInvocationWriter);

                var firstServices = new ServiceCollection();
                firstServices.AddSbomTool(LogEventLevel.Fatal);
                using var firstProvider = firstServices.BuildServiceProvider();
                firstInvocationConsole = firstProvider.GetRequiredService<IAnsiConsole>();

                Assert.IsNotNull(firstInvocationConsole);
                firstInvocationConsole.WriteLine("build #1 output");
            }

            // Build #2 reuses the process with Console.Out rebound to a new writer. The fresh DI
            // container's IAnsiConsole must write without throwing ObjectDisposedException against
            // build #1's now-disposed writer.
            using var secondInvocationWriter = new StringWriter();
            Console.SetOut(secondInvocationWriter);

            var secondServices = new ServiceCollection();
            secondServices.AddSbomTool(LogEventLevel.Fatal);
            using var secondProvider = secondServices.BuildServiceProvider();
            secondInvocationConsole = secondProvider.GetRequiredService<IAnsiConsole>();

            Assert.IsNotNull(secondInvocationConsole);
            secondInvocationConsole.WriteLine("build #2 output");
        }
        finally
        {
            Console.SetOut(originalOut);
        }

        Assert.AreNotSame(firstInvocationConsole, secondInvocationConsole, "Each AddSbomTool()-built provider must resolve its own IAnsiConsole instance.");
    }
}
