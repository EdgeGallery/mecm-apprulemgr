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
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"mecm-apprulemgr/util"
	"net/http"
	"testing"
)

type RestClientMock struct {
	mock.Mock
}

// Sends rest request and returns response
func (r *RestClientMock) sendRequest() (*http.Response, error) {
	args := r.Called()
	return args.Get(0).(*http.Response), nil
}

func TestTask(t *testing.T) {
	t.Run("TestTaskQuerySuccess", func(t *testing.T) {
		httpResponse := &http.Response{
			Status:     "200 OK",
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(SuccessResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        TaskId,
			retryInterval: 2,
			retryLimit:    2,
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := task.handleTaskQuery()

		// verify response
		assert.Equal(t, response.code, 200)
		assert.Equal(t, Success, response.progressModel.ConfigResult)
	})

	t.Run("TestTaskQueryFailure", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(FailureResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        TaskId,
			retryInterval: 2,
			retryLimit:    1,
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := task.handleTaskQuery()

		// verify response
		assert.Equal(t, response.code, 500)
		assert.Equal(t, response.progressModel.ConfigResult, Failure)
	})

	t.Run("TestTaskQueryTimeOut", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(InProgressResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        TaskId,
			retryInterval: 1,
			retryLimit:    1,
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		_, err := task.handleTaskQuery()
		assert.Equal(t, err.Error(), "app rule configuration timeout")
	})

	t.Run("TestTaskQueryFailureModel", func(t *testing.T) {
		httpResponse := &http.Response{
			StatusCode: 400,
			Body:       ioutil.NopCloser(bytes.NewBufferString(MepFailureResponse)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On(SendRequest).Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        TaskId,
			retryInterval: 1,
			retryLimit:    1,
			restClient:    &restClientMock,
			appInstanceId: AppInstanceId,
		}

		response, _ := task.handleTaskQuery()
		assert.Equal(t, response.code, 400)
		assert.Equal(t, response.progressModel.ConfigResult, Failure)
		assert.Equal(t, response.progressModel.Detailed, "duplicate entry")
	})

	t.Run("TestCreateTask", func(t *testing.T) {
		restClient, _ := createRestClient(util.CreateTaskQueryUrl(TaskId), util.Get, nil)

		task := createTask(TaskId, restClient, AppInstanceId)

		assert.Equal(t, task.appInstanceId, AppInstanceId)
		assert.Equal(t, task.taskId, TaskId)
		assert.Equal(t, task.retryLimit, 30)
		assert.Equal(t, task.retryInterval, 2)
	})
}
