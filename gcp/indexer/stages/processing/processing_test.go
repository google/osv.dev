package processing

import (
	"reflect"
	"testing"
)

func Test_processBuckets(t *testing.T) {
	type args struct {
		fileResults []*FileResult
	}
	tests := []struct {
		name string
		args args
		want map[int]*BucketNode
	}{
		{
			name: "Test bucket",
			args: args{
				fileResults: []*FileResult{
					{
						Path: "abc",
						Hash: []byte{0, 1, 2, 3, 4, 5, 6},
					},
					{
						Path: "efg",
						Hash: []byte{7, 4, 1, 3, 4, 5, 6},
					},
					{
						Path: "hji",
						Hash: []byte{1, 9, 1, 3, 4, 5, 6},
					},
				},
			},
			want: map[int]*BucketNode{
				1: {
					NodeHash:       []byte{154, 164, 97, 225, 236, 164, 8, 111, 146, 48, 170, 73, 201, 11, 12, 97},
					FilesContained: 1,
				},
				260: {
					NodeHash:       []byte{216, 219, 93, 48, 21, 44, 152, 195, 127, 147, 177, 201, 84, 210, 171, 150},
					FilesContained: 1,
				},
				265: {
					NodeHash:       []byte{8, 158, 190, 9, 14, 126, 134, 10, 210, 118, 69, 57, 158, 64, 170, 161},
					FilesContained: 1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := processBuckets(tt.args.fileResults)
			for key, value := range tt.want {
				if !reflect.DeepEqual(got[key], value) {
					t.Errorf("processBuckets() got = %v: %v, want %v", key, got, value)
				}
			}
		})
	}
}
