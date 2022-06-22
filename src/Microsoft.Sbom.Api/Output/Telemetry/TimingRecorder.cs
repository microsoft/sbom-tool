// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using Microsoft.Sbom.Api.Output.Telemetry.Entities;

namespace Microsoft.Sbom.Api.Output.Telemetry
{
    /// <summary>
    /// Records the elapsed time for a given event.
    /// </summary>
    public class TimingRecorder : IDisposable
    {
        private readonly string _eventName;
        private readonly Stopwatch _stopWatch;

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

            _eventName = eventName;
            _stopWatch = Stopwatch.StartNew();
        }

        public void Dispose()
        {
            _stopWatch.Stop();
        }

        /// <summary>
        /// Gets a value indicating whether returns true if the timings recorder is currently running.
        /// </summary>
        public bool IsRunning => _stopWatch.IsRunning;

        /// <summary>
        /// Returns a <see cref="Timing"/> object representation of this event.
        /// Make sure the timings recorder is not running before invoking this function.
        /// </summary>
        public Timing ToTiming()
        {
            if (_stopWatch.IsRunning)
            {
                throw new Exception($"Tried to read event details for an executing event.");
            }

            return new Timing
            {
                EventName = _eventName,
                TimeSpan = _stopWatch.Elapsed.ToString()
            };
        }
    }
}
