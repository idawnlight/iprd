package control

import (
	"encoding/binary"
	"fmt"
)

// protoField keeps length-delimited data as a slice of the original message.
// Signed configuration bytes must never be reconstructed by re-encoding.
type protoField struct {
	number int
	wire   int
	uint   uint64
	data   []byte
}

func readProto(data []byte) ([]protoField, error) {
	var fields []protoField
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 {
			return nil, fmt.Errorf("invalid protobuf field tag")
		}
		data = data[n:]
		field := protoField{number: int(tag >> 3), wire: int(tag & 7)}
		switch field.wire {
		case 0:
			field.uint, n = binary.Uvarint(data)
			if n <= 0 {
				return nil, fmt.Errorf("invalid protobuf varint at field %d", field.number)
			}
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return nil, fmt.Errorf("truncated protobuf fixed64 at field %d", field.number)
			}
			field.data, data = data[:8], data[8:]
		case 2:
			length, n := binary.Uvarint(data)
			if n <= 0 || length > uint64(len(data)-n) {
				return nil, fmt.Errorf("truncated protobuf bytes at field %d", field.number)
			}
			data = data[n:]
			field.data, data = data[:int(length)], data[int(length):]
		case 5:
			if len(data) < 4 {
				return nil, fmt.Errorf("truncated protobuf fixed32 at field %d", field.number)
			}
			field.data, data = data[:4], data[4:]
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type %d", field.wire)
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func protoBytes(fields []protoField, number int) [][]byte {
	var values [][]byte
	for _, field := range fields {
		if field.number == number && field.wire == 2 {
			values = append(values, field.data)
		}
	}
	return values
}

func protoByte(fields []protoField, number int) []byte {
	values := protoBytes(fields, number)
	if len(values) == 0 {
		return nil
	}
	return values[len(values)-1]
}

func protoUint(fields []protoField, number int, fallback uint64) uint64 {
	value := fallback
	for _, field := range fields {
		if field.number == number && field.wire == 0 {
			value = field.uint
		}
	}
	return value
}

func protoRepeatedUint(fields []protoField, number int) ([]uint64, error) {
	var values []uint64
	for _, field := range fields {
		if field.number != number {
			continue
		}
		switch field.wire {
		case 0:
			values = append(values, field.uint)
		case 2:
			data := field.data
			for len(data) > 0 {
				value, n := binary.Uvarint(data)
				if n <= 0 {
					return nil, fmt.Errorf("invalid packed protobuf varint")
				}
				values = append(values, value)
				data = data[n:]
			}
		default:
			return nil, fmt.Errorf("invalid protobuf integer wire type %d", field.wire)
		}
	}
	return values, nil
}
