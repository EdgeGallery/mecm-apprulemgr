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
	log "github.com/sirupsen/logrus"
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
	log.Info("mock method called")
	args := r.Called()
	return args.Get(0).(*http.Response), nil
}

func TestTask(t *testing.T) {
	t.Run("TestTaskQuerySuccess", func(t *testing.T) {
		// mock response
		progressModel := "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
			" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
			"\"configResult\": \"SUCCESS\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
		httpResponse := &http.Response{
			Status:     "200 OK",
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        "51ea862b-5806-4196-bce3-434bf9c95b18",
			retryInterval: 2,
			retryLimit:    2,
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := task.handleTaskQuery()

		// verify response
		assert.Equal(t, response.code, 200)
		assert.Equal(t, response.progressModel.ConfigResult, "SUCCESS")
	})

	t.Run("TestTaskQueryFailure", func(t *testing.T) {
		// mock response
		progressModel := "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
			" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
			"\"configResult\": \"FAILURE\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        "51ea862b-5806-4196-bce3-434bf9c95b18",
			retryInterval: 2,
			retryLimit:    1,
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := task.handleTaskQuery()

		// verify response
		assert.Equal(t, response.code, 500)
		assert.Equal(t, response.progressModel.ConfigResult, "FAILURE")
	})

	t.Run("TestTaskQueryTimeOut", func(t *testing.T) {
		// mock response
		progressModel := "{\n  \"taskId \": \"51ea862b-5806-4196-bce3-434bf9c95b18\",\n " +
			" \"appInstanceId\": \"71ea862b-5806-4196-bce3-434bf9c95b18\",\n  " +
			"\"configResult\": \"PROCESSING\",\n  \"configPhase\": \"0\",\n  \"detailed\": \"\"\n}"
		httpResponse := &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBufferString(progressModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        "51ea862b-5806-4196-bce3-434bf9c95b18",
			retryInterval: 1,
			retryLimit:    1,
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		_, err := task.handleTaskQuery()
		assert.Equal(t, err.Error(), "app rule configuration timeout")
	})

	t.Run("TestTaskQueryFailureModel", func(t *testing.T) {
		// mock response
		failureModel := "{\n  \"type\": \"error\",\n  \"title\": \"config error\",\n  \"status\": 5,\n " +
			" \"detail\": \"duplicate entry\"\n}"
		httpResponse := &http.Response{
			StatusCode: 400,
			Body:       ioutil.NopCloser(bytes.NewBufferString(failureModel)),
		}

		// mock rest client
		restClientMock := RestClientMock{}
		restClientMock.On("sendRequest").Return(httpResponse, nil)

		// create task
		task := &Task{
			taskId:        "51ea862b-5806-4196-bce3-434bf9c95b18",
			retryInterval: 1,
			retryLimit:    1,
			restClient:    &restClientMock,
			appInstanceId: "71ea862b-5806-4196-bce3-434bf9c95b18",
		}

		response, _ := task.handleTaskQuery()
		assert.Equal(t, response.code, 400)
		assert.Equal(t, response.progressModel.ConfigResult, "FAILURE")
		assert.Equal(t, response.progressModel.Detailed, "duplicate entry")
	})

	t.Run("TestCreateTask", func(t *testing.T) {
		restClient, _ := createRestClient(util.CreateTaskQueryUrl("51ea862b-5806-4196-bce3-434bf9c95b18"), util.Get, nil)

		task := createTask("51ea862b-5806-4196-bce3-434bf9c95b18", restClient, "71ea862b-5806-4196-bce3-434bf9c95b18")

		assert.Equal(t, task.appInstanceId, "71ea862b-5806-4196-bce3-434bf9c95b18")
		assert.Equal(t, task.taskId, "51ea862b-5806-4196-bce3-434bf9c95b18")
		assert.Equal(t, task.retryLimit, 30)
		assert.Equal(t, task.retryInterval, 2)
	})
}
