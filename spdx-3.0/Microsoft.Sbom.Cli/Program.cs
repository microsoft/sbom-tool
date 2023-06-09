// See https://aka.ms/new-console-template for more information

using Microsoft.Extensions.Logging;
using Microsoft.Sbom;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Creation;
using Microsoft.Sbom.Interfaces;

var loggerFactory = LoggerFactory.Create(builder =>
{
    builder
        .AddFilter("Microsoft", LogLevel.Warning)
        .AddFilter("System", LogLevel.Warning)
        .AddFilter("Program", LogLevel.Trace)
        .AddConsole();
});

ILogger logger = loggerFactory.CreateLogger<Program>();
var sourceProviders = new List<ISourceProvider>
{
    new CustomUserInfoProvider("Aasim Mallad", "aamallad@microsoft.com")
};

var g = new Generator(sourceProviders: sourceProviders, configuration: new Configuration
{
    BasePath = "C:\\Users\\aamallad\\git\\dropvalidator",
    ComponentPath = "C:\\Users\\aamallad\\git\\dropvalidator",
    OutputFilePath = "C:\\Users\\aamallad\\temp\\output.json",
    Logger = logger,
    Namespace = new Uri("https://sbom.microsoft"),
    Name = "Test",
});

await g.GenerateSBOM();