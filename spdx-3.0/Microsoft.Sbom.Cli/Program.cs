// See https://aka.ms/new-console-template for more information

using Microsoft.Extensions.Logging;
using Microsoft.Sbom;
using Microsoft.Sbom.Config;
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder
        .AddFilter("Microsoft", LogLevel.Warning)
        .AddFilter("System", LogLevel.Warning)
        .AddFilter("Program", LogLevel.Error)
        .AddConsole();
});

ILogger logger = loggerFactory.CreateLogger<Program>();
var g = new Generator(configuration: new Configuration
{
    BasePath = "C:\\Users\\aamallad\\git\\dropvalidator",
    ComponentPath = "C:\\Users\\aamallad\\git\\dropvalidator",
    OutputFilePath = "C:\\Users\\aamallad\\temp\\output.json",
    Logger = logger
});
await g.GenerateSBOM();


//await foreach (var file in f.Get())
//{
//    Console.WriteLine(file.name);
//    if (file.VerifiedUsing != null)
//    {
//        foreach (var im in file.VerifiedUsing)
//        {
//            Console.WriteLine(im);
//        }
//    }
//}