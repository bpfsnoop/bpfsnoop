// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
	"github.com/fatih/color"

	"github.com/bpfsnoop/bpfsnoop/internal/assert"
	"github.com/bpfsnoop/bpfsnoop/internal/btfx"
)

const (
	structUnionMemberInfoLen = 58
)

func findStructUnionType(typeName string) (btf.Type, error) {
	var typ btf.Type
	var err error

	err = iterateKernelBtfs(true, nil, func(spec *btf.Spec) bool {
		types, err := spec.AnyTypesByName(typeName)
		if errors.Is(err, btf.ErrNotFound) {
			return false
		}
		if err != nil {
			err = fmt.Errorf("failed to find type %q: %w", typeName, err)
			return true // stop iterating on error
		}

		for _, t := range types {
			switch t.(type) {
			case *btf.Struct, *btf.Union:
				typ = t
				return true
			}
		}

		return false
	})

	return typ, err
}

func genDepthPrefix(depth int) string {
	if depth == 0 {
		return ""
	}
	return strings.Repeat("        ", depth)
}

func printStructUnionMemberOffsetSize(w io.Writer, m *btf.Member, prevOffset btf.Bits) {
	fmt.Fprint(w, "/* ")
	defer fmt.Fprint(w, " */\n")

	// offset
	fmt.Fprintf(w, "%5d", (m.Offset + prevOffset).Bytes())

	if m.BitfieldSize != 0 {
		// bitfield size
		fmt.Fprintf(w, ":%2d %2d", m.Offset&0x7, m.BitfieldSize)
	} else {
		// size in bytes
		size, _ := btf.Sizeof(m.Type)
		fmt.Fprintf(w, "    %2d", size)
	}
}

func getFuncPointerProto(fnProto *btf.FuncProto, fnName string) string {
	var sb strings.Builder

	// func return
	retDesc := btfx.Repr(fnProto.Return)
	if strings.HasSuffix(retDesc, "*") {
		fmt.Fprint(&sb, retDesc)
	} else {
		fmt.Fprint(&sb, retDesc, " ")
	}

	// func name
	fmt.Fprintf(&sb, "(* %s)", fnName)

	// func params
	fmt.Fprint(&sb, "(")
	for i, param := range fnProto.Params {
		if i != 0 {
			fmt.Fprint(&sb, ", ")
		}

		paramType := btfx.Repr(param.Type)
		if strings.HasSuffix(paramType, "*") {
			fmt.Fprint(&sb, paramType, param.Name)
		} else {
			fmt.Fprintf(&sb, "%s %s", paramType, param.Name)
		}
	}
	fmt.Fprint(&sb, ")")

	return sb.String()
}

func printStructUnionMember(w io.Writer, m *btf.Member, prevOffset btf.Bits, depth int) {
	fmt.Fprint(w, genDepthPrefix(depth))

	typeInfo := btfx.Repr(m.Type)
	typ := mybtf.UnderlyingType(m.Type)
	ptr, isPtr := typ.(*btf.Pointer)

	infoLen := structUnionMemberInfoLen - 8*depth
	infoFormat := fmt.Sprintf("%%-%ds ", infoLen)
	if isPtr {
		if fnProto, ok := ptr.Target.(*btf.FuncProto); ok {
			typeInfo = getFuncPointerProto(fnProto, m.Name)
			fmt.Fprintf(w, infoFormat, typeInfo+";")
		} else {
			fmt.Fprintf(w, infoFormat, typeInfo+m.Name+";")
		}
	} else {
		if arr, ok := typ.(*btf.Array); ok {
			typeInfo = fmt.Sprintf("%s %s[%d]", btfx.Repr(arr.Type), m.Name, arr.Nelems)
			fmt.Fprintf(w, infoFormat, typeInfo)
		} else {
			fmt.Fprintf(w, infoFormat, typeInfo+" "+m.Name+";")
		}
	}
	printStructUnionMemberOffsetSize(w, m, prevOffset)
}

func showStructUnionMemberProto(w io.Writer, m *btf.Member, prevOffset btf.Bits, depth int) {
	if s, ok := m.Type.(*btf.Struct); ok {
		showStructProto(w, s, m.Offset+prevOffset, depth)
		if m.Name != "" {
			fmt.Fprintf(w, " %s;\n", m.Name)
		} else {
			fmt.Fprint(w, ";\n")
		}
	} else if u, ok := m.Type.(*btf.Union); ok {
		showUnionProto(w, u, m.Offset+prevOffset, depth)
		if m.Name != "" {
			fmt.Fprintf(w, " %s;\n", m.Name)
		} else {
			fmt.Fprint(w, ";\n")
		}
	} else {
		printStructUnionMember(w, m, prevOffset, depth)
	}
}

func showStructProto(w io.Writer, s *btf.Struct, prevOffset btf.Bits, depth int) {
	if s.Name != "" {
		fmt.Fprintf(w, "%sstruct %s {\n", genDepthPrefix(depth), s.Name)
	} else {
		fmt.Fprintf(w, "%sstruct {\n", genDepthPrefix(depth))
	}
	defer fmt.Fprintf(w, "%s}", genDepthPrefix(depth))

	for _, m := range s.Members {
		showStructUnionMemberProto(w, &m, prevOffset, depth+1)
	}
}

func showUnionProto(w io.Writer, u *btf.Union, prevOffset btf.Bits, depth int) {
	if u.Name != "" {
		fmt.Fprintf(w, "%sunion %s {\n", genDepthPrefix(depth), u.Name)
	} else {
		fmt.Fprintf(w, "%sunion {\n", genDepthPrefix(depth))
	}
	defer fmt.Fprintf(w, "%s}", genDepthPrefix(depth))

	for _, m := range u.Members {
		showStructUnionMemberProto(w, &m, prevOffset, depth+1)
	}
}

func showEnumProto(w io.Writer, e *btf.Enum) {
	fmt.Fprintf(w, "enum %s {\n", e.Name)
	defer fmt.Fprintf(w, "}")

	maxLen := 0
	for _, value := range e.Values {
		maxLen = max(maxLen, len(value.Name))
	}
	format := fmt.Sprintf("        %%-%ds = %%d,\n", maxLen)

	for _, value := range e.Values {
		fmt.Fprintf(w, format, value.Name, value.Value)
	}
}

func showFnProto(fn *btf.Func) {
	yellow := color.New(color.FgYellow)
	showFuncProto(os.Stdout, fn, yellow, false)
}

func showTypeProto(structs []string) {
	var sb strings.Builder

	for i, s := range structs {
		if i != 0 {
			fmt.Fprintln(&sb)
		}

		typ, err := findStructUnionType(s)
		assert.NoErr(err, "Failed to find struct/union type %q: %v", s)
		assert.NotNil(typ, "Type %q not found", s)

		typ = mybtf.UnderlyingType(typ)
		switch v := typ.(type) {
		case *btf.Struct:
			showStructProto(&sb, v, 0, 0)
		case *btf.Union:
			showUnionProto(&sb, v, 0, 0)
		case *btf.Enum:
			showEnumProto(&sb, v)
		case *btf.Func:
			showFnProto(v)
		default:
			log.Fatalf("Unsupported type %s for %q", typ, s)
		}

		fmt.Fprintln(&sb, ";")
	}

	fmt.Println(sb.String())
}
