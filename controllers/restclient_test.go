/*
 * Copyright 2020 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package controllers

import (
	"github.com/stretchr/testify/assert"
	"mecm-apprulemgr/util"
	"testing"
)

func TestRestClient(t *testing.T) {
	t.Run("TestCreateRestRequest", func(t *testing.T) {
		req, _ := createRequest(util.CreateAppdRuleUrl(AppInstanceId), util.Delete,
			nil)
		assert.Equal(t, req.Method, util.Delete)
		data := "data"
		req, _ = createRequest(util.CreateAppdRuleUrl(AppInstanceId), util.Post,
			[]byte(data))
		assert.Equal(t, req.Method, util.Post)

		req, _ = createRequest(util.CreateAppdRuleUrl(AppInstanceId), util.Put,
			[]byte(data))
		assert.Equal(t, req.Method, util.Put)

		_, err := createRequest(util.CreateAppdRuleUrl(AppInstanceId), "unknown",
			nil)
		assert.Equal(t, err.Error(), "unknown rest method")
	})
}
