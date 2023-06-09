using Microsoft.Sbom.Config;

namespace Microsoft.Sbom.Utils;
internal class IdentifierUtils
{
    private readonly Configuration configuration;

    public IdentifierUtils(Configuration configuration)
    {
        this.configuration = configuration;
    }

    internal Uri GetFileId() => GetUriInternal($"{Constants.FileIdString}-{Guid.NewGuid():N}");

    internal Uri GetPackageId() => GetUriInternal($"{Constants.PackageIdString}-{Guid.NewGuid():N}");

    internal Uri GetPersonId() => GetUriInternal($"{Constants.ActorIdString}-{Guid.NewGuid():N}");

    internal Uri GetSpdxDocumentId() => GetUriInternal($"{Constants.SpdxDocumentIdString}-{Guid.NewGuid():N}");

    private Uri GetUriInternal(string id)
    {
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
