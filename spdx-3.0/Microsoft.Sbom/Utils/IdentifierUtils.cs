namespace Microsoft.Sbom.Utils;
internal class IdentifierUtils
{
    private readonly Uri namespaceUri;

    public IdentifierUtils(Uri namespaceUri)
    {
        this.namespaceUri = namespaceUri;
    }

    internal Uri GetFileId() => GetUriInternal($"{Constants.FileIdString}-{Guid.NewGuid():N}");

    internal Uri GetPackageId() => GetUriInternal($"{Constants.PackageIdString}-{Guid.NewGuid():N}");

    internal Uri GetPersonId() => GetUriInternal($"{Constants.ActorIdString}-{Guid.NewGuid():N}");

    internal Uri GetSpdxDocumentId() => GetUriInternal($"{Constants.SpdxDocumentIdString}-{Guid.NewGuid():N}");

    internal Uri GetSbomId() => GetUriInternal(Constants.SBOMName);

    private Uri GetUriInternal(string id)
    {
        if (namespaceUri.AbsoluteUri.EndsWith("/"))
        {
            return new Uri($"{namespaceUri.AbsoluteUri.TrimEnd('/')}#{id}");
        }
        else
        {
            return new Uri($"{namespaceUri}#{id}");
        }
    }
}
