using Microsoft.Extensions.Logging;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;
using System.Threading.Channels;

namespace Microsoft.Sbom;
internal class BuildProfileOrchestrator
{
    private IList<IProcessor> processors;
    private ISerializer serializer;
    private ILogger logger;

    public BuildProfileOrchestrator(IList<IProcessor> processors, ISerializer serializer, ILogger logger)
    {
        this.processors = processors;
        this.serializer = serializer;
        this.logger = logger;
    }

    internal async Task RunAsync()
    {
        var serializerChannel = Channel.CreateUnbounded<Element>();
        var errorsChannel = Channel.CreateUnbounded<ErrorInfo>();

        using var _ = serializer;
        try
        {
            serializer.Start();

            // Start processing in a separate task
            var processingTask = Task.Run(async () =>
            {
                foreach (var processor in processors)
                {
                    await processor.ProcessAsync(serializerChannel.Writer, errorsChannel.Writer);
                }

                // Mark the channels as complete when all processing is done
                serializerChannel.Writer.Complete();
                errorsChannel.Writer.Complete();
            });

            // Start reading and serializing in parallel with processing
            var serializationTask = Task.Run(async () =>
            {
                await foreach (var element in serializerChannel.Reader.ReadAllAsync())
                {
                    serializer.Serialize(element, element.GetType());
                }
            });

            // Start logging errors in parallel with processing
            var errorLoggingTask = Task.Run(async () =>
            {
                await foreach (var errorInfo in errorsChannel.Reader.ReadAllAsync())
                {
                    logger.LogError(errorInfo.Exception, "Error in {className}: {exceptionMessage}. Additional message: {additionalMessage}", errorInfo.ClassName, errorInfo.Exception.Message, errorInfo.Message);
                }
            });

            // Wait for all tasks to complete
            await Task.WhenAll(processingTask, serializationTask, errorLoggingTask);
        }
        finally
        {
            serializer.EndDocument();
        }
    }
}