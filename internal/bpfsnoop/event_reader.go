// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/tklauser/numcpus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/bpf"
)

type rbReaders map[int]*ringbuf.Reader

// eventReader owns the typed queue and shared lifecycle for CLI and MCP.
type eventReader struct {
	output       *outputEventHandler
	outputEvents chan *parsedOutputEvent

	trace       *traceEventHandler
	traceEvents chan *parsedTraceEvent

	readers rbReaders

	ctx        context.Context
	readErrors chan error
	workers    sync.WaitGroup
}

func (rr rbReaders) close() {
	for _, reader := range rr {
		_ = reader.Close()
	}
}

func newEventRingbufReaders() (*ebpf.Map, rbReaders, error) {
	spec, err := bpf.LoadBpfsnoop()
	if err != nil {
		return nil, nil, err
	}

	if err := updateEventsMapSpec(spec); err != nil {
		return nil, nil, err
	}

	events, err := ebpf.NewMap(spec.Maps["bpfsnoop_events"])
	if err != nil {
		return nil, nil, err
	}

	readers := make(rbReaders)
	if err := populateEventMapSlots(events, spec.Maps["bpfsnoop_events"].InnerMap, readers); err != nil {
		events.Close()
		readers.close()
		return nil, nil, err
	}
	return events, readers, nil
}

// populateEventMapSlots retains readers so subsequent requests need neither
// map-in-map operations nor new ring-buffer mappings.
func populateEventMapSlots(events *ebpf.Map, inner *ebpf.MapSpec, readers map[int]*ringbuf.Reader) error {
	cpus, err := numcpus.ListOnline()
	if err != nil {
		return fmt.Errorf("read online CPUs: %w", err)
	}

	for _, cpu := range cpus {
		if uint32(cpu) >= events.MaxEntries() {
			return fmt.Errorf("online CPU %d exceeds ring-buffer map size %d", cpu, events.MaxEntries())
		}
	}

	var group errgroup.Group
	group.SetLimit(16)
	created := make([]*ringbuf.Reader, len(cpus))
	for i, cpu := range cpus {
		if readers[cpu] != nil {
			continue
		}

		group.Go(func() error {
			m, err := ebpf.NewMap(inner)
			if err != nil {
				return fmt.Errorf("CPU %d: create ring buffer: %w", cpu, err)
			}
			defer m.Close()

			if err := events.Put(uint32(cpu), m); err != nil {
				return fmt.Errorf("CPU %d: populate ring buffer: %w", cpu, err)
			}

			reader, err := ringbuf.NewReader(m)
			if err != nil {
				return fmt.Errorf("CPU %d: create reader: %w", cpu, err)
			}

			created[i] = reader
			return nil
		})
	}

	err = group.Wait()

	// Collect all successes even on failure, so the owner closes every handle.
	for i, reader := range created {
		if reader != nil {
			readers[cpus[i]] = reader
		}
	}
	return err
}

// init connects the configured handler to maps and metadata created by Boot.
// An unconfigured reader uses CLI output.
func (r *eventReader) init(maps map[string]*ebpf.Map, output io.Writer, helpers *Helpers) error {
	if r.trace != nil {
		r.trace.helpers = helpers
		return nil
	}

	if output == nil {
		return errors.New("trace output writer is nil")
	}

	r.output = NewOutputEventHandler(maps, output, helpers)
	return nil
}

func (r *eventReader) cleanup() {
	if r.output != nil {
		r.output.cleanup()
	}
}

// run parses records concurrently and consumes events serially. Only per-CPU
// ordering is guaranteed. All workers stop before output cleanup.
func (r *eventReader) run(ctx context.Context, readers map[int]*ringbuf.Reader, maxEvents uint, reused bool) error {
	r.readers = readers
	if len(r.readers) == 0 {
		return errors.New("no event readers")
	}

	runCtx, cancel := context.WithCancel(ctx)
	r.ctx = runCtx

	// Leave the unused channel nil so its receive case stays disabled.
	if r.output != nil {
		r.outputEvents = make(chan *parsedOutputEvent, len(readers))
	} else {
		r.traceEvents = make(chan *parsedTraceEvent, len(readers))
	}

	r.readErrors = make(chan error, 1)
	defer r.close(reused)
	defer cancel()

	for cpu, reader := range r.readers {
		r.workers.Go(func() {
			err := r.readCPU(cpu, reader)
			err = fmt.Errorf("CPU %d: read ring buffer: %w", cpu, err)
			select {
			case r.readErrors <- err:
			case <-r.ctx.Done():
			}
		})
	}

	return r.handleEvents(maxEvents)
}

// handleEvents owns session/output handling and the global event limit.
func (r *eventReader) handleEvents(maxEvents uint) error {
	remaining := maxEvents
	for {
		var (
			output bool
			err    error
		)

		select {
		case <-r.ctx.Done():
			return nil

		case err := <-r.readErrors:
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err

		case event := <-r.outputEvents:
			if r.ctx.Err() != nil {
				return nil
			}
			output, err = r.output.handle(event)

		case event := <-r.traceEvents:
			if r.ctx.Err() != nil {
				return nil
			}
			output, err = r.trace.handle(event)
		}
		if err != nil {
			return err
		}

		if output && maxEvents != 0 {
			remaining--
			if remaining == 0 {
				return ErrFinished
			}
		}
	}
}

func (r *eventReader) close(reused bool) {
	if reused {
		// Wake blocked reads without destroying the worker's shared readers.
		for _, reader := range r.readers {
			_ = reader.Flush()
		}
	} else {
		r.readers.close()
	}
	r.workers.Wait()
}

// readCPU parses records on a locked OS thread, bound to the ring buffer's CPU
// when that CPU is online and permitted by the thread's cpuset.
func (r *eventReader) readCPU(cpu int, reader *ringbuf.Reader) (retErr error) {
	runtime.LockOSThread()

	var original unix.CPUSet
	if err := unix.SchedGetaffinity(0, &original); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to get reader thread affinity: %w", err)
	}

	defer func() {
		if err := unix.SchedSetaffinity(0, &original); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("failed to restore reader thread affinity: %w", err))
			// Leave the thread locked so Go retires it when this worker exits.
			return
		}

		runtime.UnlockOSThread()
	}()

	var affinity unix.CPUSet
	affinity.Set(cpu)
	if err := unix.SchedSetaffinity(0, &affinity); err != nil {
		if !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("failed to bind reader thread to CPU %d: %w", cpu, err)
		}

		// Possible CPUs may be offline or excluded by a cpuset. Keep draining
		// their rings on the original affinity: system-wide tracing can emit
		// events on CPUs that this process is not allowed to run on.
		VerboseLog("CPU %d is unavailable for reader affinity; using the original thread affinity", cpu)
	}

	record := ringbuf.Record{Handle: r.readRecord}

	for {
		if err := reader.ReadInto(&record); err != nil {
			return err
		}
	}
}

// readRecord parses the borrowed sample on its CPU before enqueueing an owned
// event. Handle's return releases the sample, so parsers must not retain it.
func (r *eventReader) readRecord(data []byte) error {
	if r.ctx.Err() != nil {
		return ringbuf.ErrClosed
	}

	if r.output != nil {
		event, err := r.output.parse(data)
		if err != nil || event == nil {
			return err
		}

		select {
		case r.outputEvents <- event:
			return nil
		case <-r.ctx.Done():
			return ringbuf.ErrClosed
		}
	}

	event, err := r.trace.parse(data)
	if err != nil || event == nil {
		return err
	}

	select {
	case r.traceEvents <- event:
		return nil
	case <-r.ctx.Done():
		return ringbuf.ErrClosed
	}
}

func discardPendingRecords(reader *ringbuf.Reader) error {
	reader.SetDeadline(time.Now())
	defer reader.SetDeadline(time.Time{})

	record := ringbuf.Record{Handle: func([]byte) error { return nil }}
	for {
		err := reader.ReadInto(&record)
		if errors.Is(err, ringbuf.ErrFlushed) {
			continue
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (rr rbReaders) discard() error {
	for cpu, reader := range rr {
		if err := discardPendingRecords(reader); err != nil {
			return fmt.Errorf("CPU %d: discard pending records: %w", cpu, err)
		}
	}
	return nil
}
