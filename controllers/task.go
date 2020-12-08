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
	"errors"
	"net/http"
	"time"
)

// Represents taskInfo model
type TaskInfo struct {
	taskId        string
	retryInterval int
	retryLimit    int
	restClient    iRestClient
}

// Creates new Task info
func createTaskInfo(id string, restClient *RestClient) *TaskInfo {
	return &TaskInfo{
		taskId:        id,
		retryLimit:    10,
		retryInterval: 2,
		restClient:    restClient,
	}
}

// Sends task query request and mep for specific interval
func (t *TaskInfo) handleTaskQuery() (*Response, error) {
	for i := 0; i < t.retryLimit; i++ {
		httpResponse, err := t.restClient.sendRequest()
		if err != nil {
			return nil, err
		}
		defer httpResponse.Body.Close()

		response, err := parseResponse(httpResponse)
		if err != nil {
			return nil, err
		}

		if response.code == http.StatusOK {
			if response.progressModel.ConfigResult == "SUCCESS" ||
				response.progressModel.ConfigResult == "FAILURE" {
				return response, nil
			}

			time.Sleep(time.Duration(t.retryInterval) * time.Second)
			continue
		} else if response.code == http.StatusBadRequest ||
			response.code == http.StatusForbidden ||
			response.code == http.StatusNotFound {
			response.code = http.StatusInternalServerError
			return response, nil
		}
		return nil, errors.New("error response from mep")
	}

	return nil, errors.New("app rule config operation timeout")
}
