/*
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Package preparation provides functionality to extract tags, branches and commits from repository configurations.
package preparation

import "testing"

func Test_tagToStandardVersion(t *testing.T) {
	type args struct {
		tag string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{
				tag: "cares-1_5_0-6alpha4",
			},
			want: "1.5.0.6.4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tagToStandardVersion(tt.args.tag); got != tt.want {
				t.Errorf("tagToStandardVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
