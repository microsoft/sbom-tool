// See https://aka.ms/new-console-template for more information

using Microsoft.Sbom;
using Microsoft.Sbom.File;
using Microsoft.Sbom.JsonSerializer;

var s = new Spdx3JsonSerializer("C:\\Users\\aamallad\\temp\\t.json");

Console.WriteLine("Hello, World!");
var g = new Generator(serializer: s);
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