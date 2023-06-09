using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.ComponentDetection.Contracts.TypedComponent;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Core.Enums;

namespace Microsoft.Sbom.Package;
internal static class PackageConverter
{
    public static Spdx3_0.Software.Package Convert(ScannedComponent component)
    {
        return component.Component switch
        {
            CargoComponent cargoComponent => cargoComponent.ToPackage(),
            CondaComponent condaComponent => condaComponent.ToPackage(),
            DockerImageComponent dockerImageComponent => dockerImageComponent.ToPackage(),
            GitComponent gitComponent => gitComponent.ToPackage(),
            GoComponent goComponent => goComponent.ToPackage(),
            LinuxComponent linuxComponent => linuxComponent.ToPackage(),
            MavenComponent mavenComponent => mavenComponent.ToPackage(),
            NpmComponent npmComponent => npmComponent.ToPackage(),
            NuGetComponent nuGetComponent => nuGetComponent.ToPackage(),
            OtherComponent otherComponent => otherComponent.ToPackage(),
            PipComponent pipComponent => pipComponent.ToPackage(),
            PodComponent podComponent => podComponent.ToPackage(),
            RubyGemsComponent rubyGemsComponent => rubyGemsComponent.ToPackage(),
            null => throw new Exception($"CD returned null component"),
            _ => throw new Exception($"No conversion found for component: {component.Component.GetType()}"),
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this CargoComponent cargoComponent)
    {
        return new Spdx3_0.Software.Package(cargoComponent.Name)
        {
            packageUrl = new Uri(cargoComponent.PackageUrl.ToString()),
            packageVersion = cargoComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this CondaComponent condaComponent)
    {
        return new Spdx3_0.Software.Package(condaComponent.Name)
        {
            packageUrl = new Uri(condaComponent.PackageUrl.ToString()),
            packageVersion = condaComponent.Version,
            downloadLocation = new Uri(condaComponent.Url),
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Md5, condaComponent.MD5)
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this DockerImageComponent dockerImageComponent)
    {
        return new Spdx3_0.Software.Package(dockerImageComponent.Name)
        {
            packageUrl = new Uri(dockerImageComponent.PackageUrl.ToString()),
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Sha256, dockerImageComponent.Digest)
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this GitComponent gitComponent)
    {
        return new Spdx3_0.Software.Package(gitComponent.Id)
        {
            packageUrl = new Uri(gitComponent.PackageUrl.ToString()),
            downloadLocation = gitComponent.RepositoryUrl,
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Sha1, gitComponent.CommitHash),
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this GoComponent goComponent)
    {
        return new Spdx3_0.Software.Package(goComponent.Name)
        {
            packageUrl = new Uri(goComponent.PackageUrl.ToString()),
            packageVersion = goComponent.Version,
            verifiedUsing = new List<IntegrityMethod>
            {
                new Hash(HashAlgorithm.Sha256, goComponent.Hash),
            },
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this LinuxComponent linuxComponent)
    {
        return new Spdx3_0.Software.Package(linuxComponent.Name)
        {
            packageUrl = new Uri(linuxComponent.PackageUrl.ToString()),
            packageVersion = linuxComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this MavenComponent mavenComponent)
    {
        return new Spdx3_0.Software.Package($"{mavenComponent.GroupId}.{mavenComponent.ArtifactId}")
        {
            packageUrl = new Uri(mavenComponent.PackageUrl.ToString()),
            packageVersion = mavenComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this NpmComponent npmComponent)
    {
        return new Spdx3_0.Software.Package(npmComponent.Name)
        {
            packageUrl = new Uri(npmComponent.PackageUrl.ToString()),
            packageVersion = npmComponent.Version,
            
            // TODO use supplied by value as NPM has author
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this NuGetComponent nuGetComponent)
    {
        return new Spdx3_0.Software.Package(nuGetComponent.Name)
        {
            packageUrl = new Uri(nuGetComponent.PackageUrl.ToString()),
            packageVersion = nuGetComponent.Version,
            
            // TODO use supplied by value as nuget has author
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this OtherComponent otherComponent)
    {
        return new Spdx3_0.Software.Package(otherComponent.Name)
        {
            packageUrl = new Uri(otherComponent.PackageUrl.ToString()),
            packageVersion = otherComponent.Version,
            downloadLocation = otherComponent.DownloadUrl,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this PipComponent pipComponent)
    {
        return new Spdx3_0.Software.Package(pipComponent.Name)
        {
            packageUrl = new Uri(pipComponent.PackageUrl.ToString()),
            packageVersion = pipComponent.Version,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this PodComponent podComponent)
    {
        return new Spdx3_0.Software.Package(podComponent.Name)
        {
            packageUrl = new Uri(podComponent.PackageUrl.ToString()),
            packageVersion = podComponent.Version,
            sourceInfo = podComponent.SpecRepo,
        };
    }

    public static Spdx3_0.Software.Package ToPackage(this RubyGemsComponent rubyGemsComponent)
    {
        return new Spdx3_0.Software.Package(rubyGemsComponent.Name)
        {
            packageUrl = new Uri(rubyGemsComponent.PackageUrl.ToString()),
            packageVersion = rubyGemsComponent.Version,
            sourceInfo = rubyGemsComponent.Source,
        };
    }
}
