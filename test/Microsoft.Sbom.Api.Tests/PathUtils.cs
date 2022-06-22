using System.IO;

namespace Microsoft.Sbom.Api.Tests
{
    /// <summary>
    /// This class is responsible for providing Path functions that are provided 
    /// in either .net framework or .net core. 
    /// </summary>
    /// <remarks>
    /// Comments are from API.
    /// </remarks>
    internal class PathUtils
    {
        /// <summary>
        /// Create a relative path from one path to another. Paths will be resolved before calculating the difference.
        /// Default path comparison for the active platform will be used (OrdinalIgnoreCase for Windows or Mac, Ordinal for Unix).
        /// </summary>
        /// <param name="relativeTo">The source path the output should be relative to. This path is always considered to be a directory.</param>
        /// <param name="path">The destination path.</param>
        /// <returns>The relative path or <paramref name="path"/> if the paths don't share the same root.</returns>
        public static string GetRelativePath(string relativeTo, string path)
        {
            return Path.GetRelativePath(relativeTo, path);
        }

        /// <summary>
        /// Unlike Combine(), Join() methods do not consider rooting. They simply combine paths, ensuring that there
        /// is a directory separator between them.
        /// </summary>
        public static string Join(string path1, string path2)
        {
            return Path.Join(path1, path2);
        }

        /// <summary>
        /// Unlike Combine(), Join() methods do not consider rooting. They simply combine paths, ensuring that there
        /// is a directory separator between them.
        /// </summary>
        public static string Join(string path1, string path2, string path3)
        {
            return Path.Join(path1, path2, path3);
        }
    }
}
