// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using Microsoft.Sbom.Api.Output.Telemetry.Entities;

namespace Microsoft.Sbom.Api.Output.Telemetry;

/// <summary>
/// Records the elapsed time for a given event.
/// </summary>
public sealed class TimingRecorder : IDisposable
{
    private readonly string eventName;
    private readonly Stopwatch stopWatch;

    /// <summary>
    /// Record the duration of execution for a given event.
    /// </summary>
    /// <param name="eventName">The name of the event.</param>
    public TimingRecorder(string eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName))
        {
            throw new ArgumentException($"'{nameof(eventName)}' cannot be null or whitespace.", nameof(eventName));
        }

        this.eventName = eventName;
        stopWatch = Stopwatch.StartNew();
    }

    public void Dispose()
    {
        stopWatch.Stop();
    }

    /// <summary>
    /// Gets a value indicating whether returns true if the timings recorder is currently running.
    /// </summary>
    public bool IsRunning => stopWatch.IsRunning;

    /// <summary>
    /// Returns a <see cref="Timing"/> object representation of this event.
    /// Make sure the timings recorder is not running before invoking this function.
    /// </summary>
    public Timing ToTiming()
    {
        if (stopWatch.IsRunning)
        {
            throw new Exception($"Tried to read event details for an executing event.");
        }

        return new Timing
        {
            EventName = eventName,
            TimeSpan = stopWatch.Elapsed.ToString()
        };
    }
}
