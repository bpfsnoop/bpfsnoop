// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/bpfsnoop/bpfsnoop/internal/cc"
)

type bpfMaps struct {
	maps    map[cc.BPFMapID]cc.BPFMap
	handles []*ebpf.Map
}

func (m *bpfMaps) Close() error {
	var err error
	for _, handle := range m.handles {
		err = errors.Join(err, handle.Close())
	}
	m.handles = nil
	clear(m.maps)
	return err
}

func openBPFMaps(ids []cc.BPFMapID) (*bpfMaps, error) {
	var maps bpfMaps

	fail := func(err error) (*bpfMaps, error) {
		return nil, errors.Join(err, maps.Close())
	}

	slices.SortFunc(ids, func(a, b cc.BPFMapID) int {
		return strings.Compare(a.String(), b.String())
	})
	ids = slices.Compact(ids)
	maps.maps = make(map[cc.BPFMapID]cc.BPFMap, len(ids))

	byID := make(map[ebpf.MapID]cc.BPFMap)
	var arenaID ebpf.MapID
	for _, id := range ids {
		handle, info, err := openBPFMap(id)
		if err != nil {
			return fail(err)
		}
		mapID, _ := info.ID()
		if metadata, ok := byID[mapID]; ok {
			if err := handle.Close(); err != nil {
				return fail(err)
			}

			maps.maps[id] = metadata
			continue
		}

		maps.handles = append(maps.handles, handle)

		// An arena map has no keys or values, but memory, for arena(). The
		// expressions go into one bpf prog, which can use only one arena.
		if info.Type == ebpf.Arena {
			if arenaID != 0 {
				return fail(fmt.Errorf("arena(%s): a bpf prog can use only one arena, but arena map %d is used too", id, arenaID))
			}
			arenaID = mapID

			metadata := cc.BPFMap{FD: handle.FD(), Type: info.Type, MaxEntries: info.MaxEntries}
			maps.maps[id] = metadata
			byID[mapID] = metadata
			continue
		}

		key, value, err := bpfMapTypes(handle)
		if err != nil {
			return fail(fmt.Errorf("map_lookup(%s) failed to resolve map BTF: %w", id, err))
		}

		size, err := btf.Sizeof(value)
		if err != nil || size == 0 || uint32(size) != info.ValueSize {
			return fail(fmt.Errorf("map_lookup(%s) value BTF size %d does not match map value size %d: %v", id, size, info.ValueSize, err))
		}

		if key != nil {
			size, err := btf.Sizeof(key)
			if err != nil || size == 0 || uint32(size) != info.KeySize {
				return fail(fmt.Errorf("map_lookup(%s) key BTF size %d does not match map key size %d: %v", id, size, info.KeySize, err))
			}
		}

		metadata := cc.BPFMap{
			FD:         handle.FD(),
			Type:       info.Type,
			MaxEntries: info.MaxEntries,
			KeySize:    info.KeySize,
			Key:        key,
			Value:      value,
		}
		maps.maps[id] = metadata
		byID[mapID] = metadata
	}

	return &maps, nil
}

func openBPFMap(mapID cc.BPFMapID) (*ebpf.Map, *ebpf.MapInfo, error) {
	if id := mapID.ID; id != 0 {
		handle, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open map from id %d: %w", id, err)
		}

		info, err := handle.Info()
		if err != nil {
			err = fmt.Errorf("failed to open map info of map id %d: %w", id, err)
			return nil, nil, errors.Join(err, handle.Close())
		}

		return handle, info, nil
	}

	var found *ebpf.Map
	var foundInfo *ebpf.MapInfo
	fail := func(err error) (*ebpf.Map, *ebpf.MapInfo, error) {
		if found != nil {
			err = errors.Join(err, found.Close())
		}
		return nil, nil, err
	}

	for id := ebpf.MapID(0); ; {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			if found == nil {
				return fail(fmt.Errorf("map %q not found", mapID.Name))
			}
			return found, foundInfo, nil
		}
		if err != nil {
			return fail(err)
		}

		id = next
		handle, err := ebpf.NewMapFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fail(err)
		}

		info, err := handle.Info()
		if err != nil {
			return fail(errors.Join(err, handle.Close()))
		}

		if info.Name != mapID.Name {
			if err := handle.Close(); err != nil {
				return fail(err)
			}
			continue
		}

		if found != nil {
			err := fmt.Errorf("found multiple maps named %q; use an integer map ID instead", mapID.Name)
			return fail(errors.Join(err, handle.Close()))
		}

		found, foundInfo = handle, info
	}
}

func bpfMapTypes(m *ebpf.Map) (btf.Type, btf.Type, error) {
	// ebpf.MapInfo doesn't expose the key and value BTF type IDs. Read the
	// UAPI prefix directly, then resolve both IDs in the map's BTF object.

	var info struct {
		Type, ID, KeySize, ValueSize, MaxEntries, Flags uint32
		Name                                            [16]byte
		Ifindex, VmlinuxValueTypeID                     uint32
		NetnsDev, NetnsIno                              uint64
		BTFID, KeyTypeID, ValueTypeID                   uint32
		_                                               uint32
	}

	attr := struct {
		FD, Size uint32
		Info     uint64
	}{
		uint32(m.FD()),
		uint32(unsafe.Sizeof(info)),
		uint64(uintptr(unsafe.Pointer(&info))),
	}

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return nil, nil, fmt.Errorf("failed to get map BTF type IDs: %w", errno)
	}

	if info.ValueTypeID == 0 {
		return nil, nil, fmt.Errorf("map has no value BTF type ID")
	}

	handle, err := m.Handle()
	if err != nil {
		return nil, nil, err
	}

	defer handle.Close()
	spec, err := handle.Spec(nil)
	if err != nil {
		return nil, nil, err
	}

	value, err := spec.TypeByID(btf.TypeID(info.ValueTypeID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve map value BTF: %w", err)
	}
	var key btf.Type
	if info.KeyTypeID != 0 {
		key, err = spec.TypeByID(btf.TypeID(info.KeyTypeID))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve map key BTF: %w", err)
		}
	}
	return key, value, nil
}
