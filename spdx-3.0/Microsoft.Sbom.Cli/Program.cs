// See https://aka.ms/new-console-template for more information
using Microsoft.Sbom;

Console.WriteLine("Hello, World!");

var f = new FileSourceProvider("C:\\Users\\aamallad\\temp\\test");

await foreach (var file in f.Get())
{
    Console.WriteLine(file.name);
}