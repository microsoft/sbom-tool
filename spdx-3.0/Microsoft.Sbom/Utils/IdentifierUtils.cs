using Microsoft.Sbom.Config;

namespace Microsoft.Sbom.Utils;
internal class IdentifierUtils
{
    private readonly Configuration configuration;

    public IdentifierUtils(Configuration configuration)
    {
        this.configuration = configuration;
    }

    internal Uri GetFileId()
    {
        var id = $"{Constants.FileIdString}-{Guid.NewGuid():N}";
        if (configuration.Namespace.AbsoluteUri.EndsWith("/"))
        {
            return new Uri($"{configuration.Namespace.AbsoluteUri.TrimEnd('/')}#{id}");
        }
        else
        {
            return new Uri($"{configuration.Namespace}#{id}");
        }
    }

    internal Uri GetPackageId()
    {
        var id = $"{Constants.PackageIdString}-{Guid.NewGuid():N}";
        if (configuration.Namespace.AbsoluteUri.EndsWith("/"))
        {
            return new Uri($"{configuration.Namespace.AbsoluteUri.TrimEnd('/')}#{id}");
        }
        else
        {
            return new Uri($"{configuration.Namespace}#{id}");
        }
    }
}
