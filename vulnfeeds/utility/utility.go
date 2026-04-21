package utility

import (
	"cmp"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// SliceEqual returns true if two slices have identical items in the same order
func SliceEqual[K comparable](a []K, b []K) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// SliceEqualUnordered returns true if two slices have identical items, in any order
func SliceEqualUnordered[K comparable](a []K, b []K) bool {
	if len(a) != len(b) {
		return false
	}
	aSet := make(map[K]struct{}, len(a))
	bSet := make(map[K]struct{}, len(b))
	for i := range a {
		aSet[a[i]] = struct{}{}
		bSet[b[i]] = struct{}{}
	}
	for k := range aSet {
		_, ok := bSet[k]
		if !ok {
			return false
		}
	}

	return true
}

// Checks if a URL is to a supported repo.
func IsRepoURL(url string) bool {
	re := regexp.MustCompile(`http[s]?:\/\/(?:c?git(?:hub|lab)?)\.|\.git$`)

	return re.MatchString(url)
}

// NewStructpbFromMap converts a map[string]any to a *structpb.Struct,
// which is suitable for OSV's database_specific field.
func NewStructpbFromMap(v map[string]any) (*structpb.Struct, error) {
	x := &structpb.Struct{Fields: make(map[string]*structpb.Value, len(v))}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		var err error
		x.Fields[k], err = newStructpbValue(v[k])
		if err != nil {
			return nil, err
		}
	}

	return x, nil
}

// newStructpbValue is a generic converter that takes any Go type and returns a *structpb.Value.
func newStructpbValue(v any) (*structpb.Value, error) {
	if v == nil {
		return structpb.NewNullValue(), nil
	}

	if msg, ok := v.(proto.Message); ok {
		val, err := protoToAny(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to convert proto message: %w", err)
		}

		return structpb.NewValue(val)
	}

	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Slice:
		var anyList []any
		for i := range val.Len() {
			anyList = append(anyList, val.Index(i).Interface())
		}

		return structpbValueFromList(anyList)
	case reflect.Map:
		if val.Type().Key().Kind() == reflect.String {
			keys := val.MapKeys()
			slices.SortFunc(keys, func(a, b reflect.Value) int {
				return cmp.Compare(a.String(), b.String())
			})

			x := &structpb.Struct{Fields: make(map[string]*structpb.Value, len(keys))}
			for _, k := range keys {
				var err error
				x.Fields[k.String()], err = newStructpbValue(val.MapIndex(k).Interface())
				if err != nil {
					return nil, err
				}
			}

			return structpb.NewStructValue(x), nil
		}

		return structpb.NewValue(v)
	default:
		return structpb.NewValue(v)
	}
}

// structpbValueFromList converts a generic slice into a *structpb.Value that
// represents a list.
// It iterates through the list, converting any proto.Message elements into
// any type via JSON marshalling, while other elements are included as-is.
func structpbValueFromList(list []any) (*structpb.Value, error) {
	values := make([]*structpb.Value, 0, len(list))
	for i, v := range list {
		val, err := newStructpbValue(v)
		if err != nil {
			return nil, fmt.Errorf("failed to convert item %d: %w", i, err)
		}
		values = append(values, val)
	}

	return structpb.NewListValue(&structpb.ListValue{Values: values}), nil
}

// protoToAny converts a proto.Message to an any type by marshalling to JSON
// with protojson and then unmarshalling into an `any`.
func protoToAny(p proto.Message) (any, error) {
	b, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("protojson.Marshal: %w", err)
	}

	var result any
	err = json.Unmarshal(b, &result)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}

	return result, nil
}
