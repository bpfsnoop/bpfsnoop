// Copyright 2026 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btfx

import (
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// TypeMember describes one immediate member of a BTF struct or union.
type TypeMember struct {
	Name         string
	Type         string
	OffsetBits   uint32
	BitfieldSize uint32
}

// TypeArgument describes one BTF function-prototype argument.
type TypeArgument struct {
	Name string
	Type string
}

// TypeEnumValue describes one named BTF enum value.
type TypeEnumValue struct {
	Name  string
	Value string
}

// TypeVariable describes one entry in a BTF data section.
type TypeVariable struct {
	Kind        string
	Name        string
	Type        string
	OffsetBytes uint32
	SizeBytes   uint32
}

// TypeDetails contains presentation-neutral metadata extracted from a BTF type.
type TypeDetails struct {
	Kind         string
	Size         *uint32
	Members      []TypeMember
	Arguments    []TypeArgument
	ReturnType   string
	TargetType   string
	ElementType  string
	IndexType    string
	ElementCount *uint32
	Encoding     string
	EnumSigned   *bool
	EnumValues   []TypeEnumValue
	Linkage      string
	Variables    []TypeVariable
	ForwardKind  string
	Tags         []string
}

// FuncPrototype formats a BTF function and its prototype as a C declaration.
func FuncPrototype(fn *btf.Func) string {
	proto := fn.Type.(*btf.FuncProto)
	var output strings.Builder

	returnType := Repr(proto.Return)
	output.WriteString(returnType)
	if !strings.HasSuffix(returnType, "*") {
		output.WriteByte(' ')
	}
	output.WriteString(fn.Name)
	output.WriteByte('(')
	for i, param := range proto.Params {
		if i != 0 {
			output.WriteString(", ")
		}
		paramType := Repr(param.Type)
		output.WriteString(paramType)
		if param.Name != "" {
			if !strings.HasSuffix(paramType, "*") {
				output.WriteByte(' ')
			}
			output.WriteString(param.Name)
		}
	}
	output.WriteByte(')')

	return output.String()
}

// TypeKind returns a stable name for a BTF type's concrete kind.
func TypeKind(typ btf.Type) string {
	switch typ.(type) {
	case *btf.Void:
		return "void"
	case *btf.Int:
		return "int"
	case *btf.Pointer:
		return "pointer"
	case *btf.Array:
		return "array"
	case *btf.Struct:
		return "struct"
	case *btf.Union:
		return "union"
	case *btf.Enum:
		return "enum"
	case *btf.Fwd:
		return "forward"
	case *btf.Typedef:
		return "typedef"
	case *btf.Volatile:
		return "volatile"
	case *btf.Const:
		return "const"
	case *btf.Restrict:
		return "restrict"
	case *btf.Var:
		return "variable"
	case *btf.Datasec:
		return "data_section"
	case *btf.Float:
		return "float"
	case *btf.Func:
		return "func"
	case *btf.FuncProto:
		return "func_proto"
	case *btf.TypeTag:
		return "type_tag"
	default:
		return "other"
	}
}

func detailType(typ btf.Type) btf.Type {
	for {
		switch value := typ.(type) {
		case *btf.Func:
			typ = value.Type
		case *btf.Typedef:
			typ = value.Type
		case *btf.Volatile:
			typ = value.Type
		case *btf.Const:
			typ = value.Type
		case *btf.Restrict:
			typ = value.Type
		case *btf.TypeTag:
			typ = value.Type
		case *btf.Pointer:
			target := detailType(value.Target)
			if _, ok := target.(*btf.FuncProto); ok {
				return target
			}
			return typ
		default:
			return typ
		}
	}
}

// DescribeType extracts the structural metadata of a BTF type.
func DescribeType(typ btf.Type) TypeDetails {
	details := TypeDetails{Kind: TypeKind(typ)}
	switch value := typ.(type) {
	case *btf.Typedef:
		details.TargetType = Repr(value.Type)
		details.Tags = slices.Clone(value.Tags)
	case *btf.Struct:
		details.Tags = slices.Clone(value.Tags)
	case *btf.Union:
		details.Tags = slices.Clone(value.Tags)
	case *btf.Func:
		details.Linkage = value.Linkage.String()
		details.Tags = slices.Clone(value.Tags)
	case *btf.Var:
		details.TargetType = Repr(value.Type)
		details.Linkage = value.Linkage.String()
		details.Tags = slices.Clone(value.Tags)
	}

	switch value := detailType(typ).(type) {
	case *btf.Int:
		size := value.Size
		details.Size = &size
		details.Encoding = value.Encoding.String()
	case *btf.Pointer:
		size := uint32(8)
		details.Size = &size
		details.TargetType = Repr(value.Target)
	case *btf.Array:
		details.ElementType = Repr(value.Type)
		details.IndexType = Repr(value.Index)
		count := value.Nelems
		details.ElementCount = &count
		if size, err := btf.Sizeof(value); err == nil {
			size := uint32(size)
			details.Size = &size
		}
	case *btf.Struct:
		details.Size = &value.Size
		details.Members = describeMembers(value.Members)
	case *btf.Union:
		details.Size = &value.Size
		details.Members = describeMembers(value.Members)
	case *btf.FuncProto:
		details.Arguments = make([]TypeArgument, 0, len(value.Params))
		for _, argument := range value.Params {
			details.Arguments = append(details.Arguments, TypeArgument{Name: argument.Name, Type: Repr(argument.Type)})
		}
		details.ReturnType = Repr(value.Return)
	case *btf.Enum:
		details.Size = &value.Size
		details.EnumSigned = &value.Signed
		details.EnumValues = make([]TypeEnumValue, 0, len(value.Values))
		for _, enumValue := range value.Values {
			var valueText string
			if value.Signed {
				shift := 64 - min(value.Size*8, 64)
				valueText = strconv.FormatInt(int64(enumValue.Value<<shift)>>shift, 10)
			} else {
				valueText = strconv.FormatUint(enumValue.Value, 10)
			}
			details.EnumValues = append(details.EnumValues, TypeEnumValue{Name: enumValue.Name, Value: valueText})
		}
	case *btf.Fwd:
		details.ForwardKind = value.Kind.String()
	case *btf.Var:
		details.TargetType = Repr(value.Type)
		details.Linkage = value.Linkage.String()
	case *btf.Datasec:
		details.Size = &value.Size
		details.Variables = make([]TypeVariable, 0, len(value.Vars))
		for _, variable := range value.Vars {
			variableInfo := TypeVariable{
				Kind:        TypeKind(variable.Type),
				Name:        variable.Type.TypeName(),
				Type:        Repr(variable.Type),
				OffsetBytes: variable.Offset,
				SizeBytes:   variable.Size,
			}
			switch typedVariable := variable.Type.(type) {
			case *btf.Var:
				variableInfo.Type = Repr(typedVariable.Type)
			case *btf.Func:
				variableInfo.Type = FuncPrototype(typedVariable)
			}
			details.Variables = append(details.Variables, variableInfo)
		}
	case *btf.Float:
		details.Size = &value.Size
	}

	return details
}

func describeMembers(members []btf.Member) []TypeMember {
	result := make([]TypeMember, 0, len(members))
	for _, member := range members {
		result = append(result, TypeMember{
			Name:         member.Name,
			Type:         Repr(member.Type),
			OffsetBits:   uint32(member.Offset),
			BitfieldSize: uint32(member.BitfieldSize),
		})
	}
	return result
}
