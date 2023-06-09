using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Utils;
internal static class PackageConverter
{
    public static Spdx3_0.Software.Package Convert(TypedComponent component, Uri id)
    {
        return component switch
        {
            CargoComponent cargoComponent => cargoComponent.ToPackage(id),
            CondaComponent condaComponent => condaComponent.ToPackage(id),
            DockerImageComponent dockerImageComponent => dockerImageComponent.ToPackage(id),
            GitComponent gitComponent => gitComponent.ToPackage(id),
            GoComponent goComponent => goComponent.ToPackage(id),
            LinuxComponent linuxComponent => linuxComponent.ToPackage(id),
            MavenComponent mavenComponent => mavenComponent.ToPackage(id),
            NpmComponent npmComponent => npmComponent.ToPackage(id),
            NuGetComponent nuGetComponent => nuGetComponent.ToPackage(id),
            OtherComponent otherComponent => otherComponent.ToPackage(id),
            PipComponent pipComponent => pipComponent.ToPackage(id),
            PodComponent podComponent => podComponent.ToPackage(id),
            RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToPackage(id),
            null => throw new Exception($"CD returned null component"),
            _ => throw new Exception($"No conversion found for component: {component.GetType()}"),
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this CargoComponent cargoComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(cargoComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(cargoComponent.PackageUrl.ToString()),
            packageVersion = cargoComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this CondaComponent condaComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(condaComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(condaComponent.PackageUrl.ToString()),
            packageVersion = condaComponent.Version,
            downloadLocation = new Uri(condaComponent.Url),
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Md5, condaComponent.MD5)
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this DockerImageComponent dockerImageComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(dockerImageComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(dockerImageComponent.PackageUrl.ToString()),
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Sha256, dockerImageComponent.Digest)
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this GitComponent gitComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(gitComponent.Id)
        {
            spdxId = id,
            packageUrl = new Uri(gitComponent.PackageUrl.ToString()),
            downloadLocation = gitComponent.RepositoryUrl,
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Sha1, gitComponent.CommitHash),
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this GoComponent goComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(goComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(goComponent.PackageUrl.ToString()),
            packageVersion = goComponent.Version,
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Sha256, goComponent.Hash),
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this LinuxComponent linuxComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(linuxComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(linuxComponent.PackageUrl.ToString()),
            packageVersion = linuxComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this MavenComponent mavenComponent, Uri id)
    {
        return new Spdx3_0.Software.Package($"{mavenComponent.GroupId}.{mavenComponent.ArtifactId}")
        {
            spdxId = id,
            packageUrl = new Uri(mavenComponent.PackageUrl.ToString()),
            packageVersion = mavenComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this NpmComponent npmComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(npmComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(npmComponent.PackageUrl.ToString()),
            packageVersion = npmComponent.Version,

            // TODO use supplied by value as NPM has author
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this NuGetComponent nuGetComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(nuGetComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(nuGetComponent.PackageUrl.ToString()),
            packageVersion = nuGetComponent.Version,

            // TODO use supplied by value as nuget has author
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this OtherComponent otherComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(otherComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(otherComponent.PackageUrl.ToString()),
            packageVersion = otherComponent.Version,
            downloadLocation = otherComponent.DownloadUrl,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this PipComponent pipComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(pipComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(pipComponent.PackageUrl.ToString()),
            packageVersion = pipComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this PodComponent podComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(podComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(podComponent.PackageUrl.ToString()),
            packageVersion = podComponent.Version,
            sourceInfo = podComponent.SpecRepo,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this RubyGemsComponent rubyGemsComponent, Uri id)
    {
        return new Spdx3_0.Software.Package(rubyGemsComponent.Name)
        {
            spdxId = id,
            packageUrl = new Uri(rubyGemsComponent.PackageUrl.ToString()),
            packageVersion = rubyGemsComponent.Version,
            sourceInfo = rubyGemsComponent.Source,
        };
    }
}