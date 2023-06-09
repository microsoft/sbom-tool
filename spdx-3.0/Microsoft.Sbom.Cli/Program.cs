// See https://aka.ms/new-console-template for more information

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Sbom;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Creation;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.JsonSerializer;

internal class Program
{
    /// <summary>
    /// Microsoft SPDX 3.0.0 SBOM Generator.
    /// </summary>
    /// <param name="verbosity">The level of detailed logs to display.</param>
    /// <param name="userName">The name of the creator of the SBOM.</param>
    /// <param name="userEmail">The email of the creator of the SBOM.</param>
    /// <param name="artifactsPath">The path that will be scanned for file artifacts to add to the SBOM.</param>
    /// <param name="componentsPath">The path that will be scanned for package artifacts to add to the SBOM.</param>
    /// <param name="outputFilePath">The path of the SBOM file which will be generated.</param>
    /// <param name="namespaceUri">The namespace used in this SBOM.</param>
    /// <param name="documentName">The name of the SPDX document in this SBOM.</param>
    /// <returns></returns>
    private static async Task Main(
                                   LogLevel verbosity,
                                   string userName,
                                   string userEmail,
                                   string artifactsPath,
                                   string componentsPath,
                                   string outputFilePath,
                                   Uri namespaceUri,
                                   string documentName)
    {
        var start = Stopwatch.StartNew();
        Console.WriteLine("Microsoft SPDX 3.0.0 SBOM Generator");
        Console.WriteLine("===================================");

        // Create logger
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .AddFilter("Program", verbosity)
                .AddConsole();
        });
        ILogger logger = loggerFactory.CreateLogger<Program>();

        var sourceProviders = new List<ISourceProvider>();
        var configuration = new Configuration();

        // Add custom user info provider if needed
        if (!string.IsNullOrEmpty(userName) || !string.IsNullOrEmpty(userEmail))
        {
            sourceProviders.Add(new CustomUserInfoProvider(userName, userEmail));
        }

        if (!string.IsNullOrEmpty(artifactsPath))
        {
            configuration.BasePath = artifactsPath;
        }

        if (!string.IsNullOrEmpty(componentsPath))
        {
            configuration.ComponentPath = componentsPath;
        }

        if (!string.IsNullOrEmpty(documentName))
        {
            configuration.Name = documentName;
        }
        
        if (namespaceUri != null)
        {
            configuration.Namespace = namespaceUri;
        }

        outputFilePath ??= Path.Combine(Path.GetTempPath(), $"sbom-{Guid.NewGuid()}.json");

        var generator = new Generator.Builder()
                                .WithSourceProviders(sourceProviders)
                                .WithConfiguration(configuration)
                                .SerializeTo(new Spdx3JsonSerializer(outputFilePath, logger))
                                .AddLogging(logger)
                                .Build();

        await generator.GenerateSBOM();
        loggerFactory.Dispose();

        Console.WriteLine($"SBOM file generated at {outputFilePath}");
        Console.WriteLine($"SBOM generation took {start.Elapsed.TotalSeconds} seconds.");
    }
}