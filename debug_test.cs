using System;
using Microsoft.Sbom.Api.Utils;

class Program
{
    static void Main()
    {
        var basePath = @"C:\test";
        var pattern = @"src\*\file.txt";
        var filePath = @"C:\test\src\component\file.txt";
        
        Console.WriteLine($"Pattern: {pattern}");
        Console.WriteLine($"FilePath: {filePath}");
        Console.WriteLine($"BasePath: {basePath}");
        Console.WriteLine($"Result: {PathPatternMatcher.IsMatch(filePath, pattern, basePath)}");
        
        // Test simple pattern too
        var simplePattern = "*.txt";
        var simpleFile = @"C:\test\file.txt";
        Console.WriteLine($"Simple Pattern: {simplePattern}");
        Console.WriteLine($"Simple File: {simpleFile}");
        Console.WriteLine($"Simple Result: {PathPatternMatcher.IsMatch(simpleFile, simplePattern, basePath)}");
    }
}