// See https://aka.ms/new-console-template for more information

using Microsoft.Sbom;
using Microsoft.Sbom.Config;

var g = new Generator(configuration: new Configuration
{
    BasePath = "C:\\Users\\aamallad\\git\\dropvalidator",
    ComponentPath = "C:\\Users\\aamallad\\git\\dropvalidator",
    OutputFilePath = "C:\\Users\\aamallad\\temp\\output.json"
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