/*
 *    Copyright 2022 Django Cass
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

package adapter

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFirst(t *testing.T) {
	var cases = []struct {
		in  []string
		out string
	}{
		{
			[]string{"a", "b"},
			"a",
		},
		{
			nil,
			"",
		},
	}
	for _, tt := range cases {
		t.Run(tt.out, func(t *testing.T) {
			assert.EqualValues(t, tt.out, first(tt.in))
		})
	}
}
