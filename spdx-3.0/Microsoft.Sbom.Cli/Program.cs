// See https://aka.ms/new-console-template for more information

using Microsoft.Extensions.Logging;
using Microsoft.Sbom;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Creation;
using Microsoft.Sbom.Interfaces;

// Create logger
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder
        .AddFilter("Microsoft", LogLevel.Error)
        .AddFilter("System", LogLevel.Error)
        .AddFilter("Program", LogLevel.Trace)
        .AddConsole();
});
ILogger logger = loggerFactory.CreateLogger<Program>();

// Add custom user info provider
var sourceProviders = new List<ISourceProvider>
{
    new CustomUserInfoProvider("Aasim Malladi", "aamallad@microsoft.com")
};

var testPath = "C:\\Users\\aamallad\\git\\WebApplication1";
var configuration = new Configuration
{
    BasePath = testPath,
    ComponentPath = testPath,
    OutputFilePath = "C:\\Users\\aamallad\\temp\\output.json",
    Namespace = new Uri("https://sbom.microsoft"),
    Name = "Test",
};

var generator = new Generator.Builder()
                        .WithSourceProviders(sourceProviders)
                        .WithConfiguration(configuration)
                        .AddLogging(logger)
                        .Build();

await generator.GenerateSBOM();