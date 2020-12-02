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

package test

import (
	"github.com/astaxie/beego"
	"github.com/stretchr/testify/assert"
	_ "mecm-apprulemgr/routers"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEndPoint(t *testing.T) {

	t.Run("TestHealthCheck", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/apprulemgr/v1/health", nil)
		w := httptest.NewRecorder()
		beego.BeeApp.Handlers.ServeHTTP(w, r)
		assert.Equal(t, "ok", w.Body.String(), "Health check output is not ok")
		assert.Equal(t, 200, w.Code, "Health Check output code is not 200")
	})
}
