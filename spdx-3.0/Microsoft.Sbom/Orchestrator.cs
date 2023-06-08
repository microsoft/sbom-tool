using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Interfaces;

namespace Microsoft.Sbom;
internal class Orchestrator
{   
    private readonly IList<IProcessor> processors;
    private readonly ISerializer serializer;
    private readonly ILogger logger;

    internal Orchestrator(IList<IProcessor> processors, ISerializer serializer, ILogger logger)
    {
        this.processors = processors;
        this.serializer = serializer;
        this.logger = logger;
    }

    internal async Task RunAsync()
    {
        // Figure out profile.
        // We will for now only generate build profile

        var buildProfileOrchestrator = new BuildProfileOrchestrator(processors, serializer, logger);
        await buildProfileOrchestrator.RunAsync();
    }
}
