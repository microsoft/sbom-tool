using System;
using System.IO;
using System.Text.RegularExpressions;

class DebugPattern
{
    static void Main()
    {
        var basePath = @"C:\test";
        var pattern = @"src\*\file.txt";
        var filePath = @"C:\test\src\component\file.txt";
        
        Console.WriteLine($"Pattern: {pattern}");
        Console.WriteLine($"FilePath: {filePath}");
        Console.WriteLine($"BasePath: {basePath}");
        
        // Normalize
        var normalizedFilePath = Path.GetFullPath(filePath);
        var combinedPath = Path.Combine(basePath, pattern);
        var normalizedPattern = Path.GetFullPath(combinedPath);
        
        Console.WriteLine($"Normalized FilePath: {normalizedFilePath}");
        Console.WriteLine($"Combined Pattern Path: {combinedPath}");
        Console.WriteLine($"Normalized Pattern: {normalizedPattern}");
        
        // Convert to regex
        var regex = ConvertGlobToRegex(normalizedPattern);
        Console.WriteLine($"Regex: {regex}");
        
        var match = Regex.IsMatch(normalizedFilePath, regex, RegexOptions.IgnoreCase);
        Console.WriteLine($"Match: {match}");
    }
    
    static string ConvertGlobToRegex(string globPattern)
    {
        var regexPattern = new System.Text.StringBuilder();

        for (var i = 0; i < globPattern.Length; i++)
        {
            var c = globPattern[i];

            switch (c)
            {
                case '*':
                    if (i + 1 < globPattern.Length && globPattern[i + 1] == '*')
                    {
                        regexPattern.Append(".*");
                        i++;
                    }
                    else
                    {
                        regexPattern.Append(@"[^\\\/]*");
                    }
                    break;
                case '?':
                    regexPattern.Append('.');
                    break;
                case '\\':
                case '/':
                    regexPattern.Append(@"[\\\/]");
                    break;
                default:
                    if ("()[]{}^$+.|".Contains(c))
                    {
                        regexPattern.Append('\\');
                    }
                    regexPattern.Append(c);
                    break;
            }
        }

        return "^" + regexPattern.ToString() + ".*$";
    }
}