using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;

namespace Microsoft.Sbom.Creation;
public class CustomUserInfoProvider : ISourceProvider
{
    private readonly string userName;
    private readonly string userEmail;

    public CustomUserInfoProvider(string? userName, string? userEmail)
    {
        this.userName = userName ?? string.Empty;
        this.userEmail = userEmail ?? string.Empty;
    }

    public SourceType SourceType => SourceType.UserInfo;

    public async IAsyncEnumerable<object> Get()
    {
        yield return await Task.FromResult(new UserInfo(userName, userEmail));
    }
}
