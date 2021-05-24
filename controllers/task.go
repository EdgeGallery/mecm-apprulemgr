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
	log "github.com/sirupsen/logrus"
	"mecm-apprulemgr/util"
	"net/http"
	"time"
)

// Represents taskInfo model
type Task struct {
	taskId        string
	retryInterval int
	retryLimit    int
	restClient    iRestClient
	appInstanceId string
}

// Creates new Task info
func createTask(id string, restClient *RestClient, appInstanceId string) *Task {
	return &Task{
		taskId:        id,
		retryLimit:    util.GetRetryLimit(),
		retryInterval: util.GetRetryInterval(),
		restClient:    restClient,
		appInstanceId: appInstanceId,
	}
}

// Sends task query request and mep for specific interval
func (t *Task) handleTaskQuery() (*Response, error) {
	for i := 0; i < t.retryLimit; i++ {
		httpResponse, err := t.restClient.sendRequest()
		if err != nil {
			return nil, err
		}
		defer httpResponse.Body.Close()

		response, err := parseResponse(httpResponse, t.appInstanceId)
		if err != nil {
			return nil, err
		}

		if response.code != http.StatusOK {
			return response, nil
		}

		if response.progressModel.ConfigResult == util.Success {
			log.Info(util.AppRuleConfigSuccess)
			return response, nil
		} else if response.progressModel.ConfigResult == util.Failure {
			log.Error(util.AppRuleConfigFailed)
			response.code = util.InternalServerError
			return response, nil
		}

		time.Sleep(time.Duration(t.retryInterval) * time.Second)
	}

	return nil, errors.New(util.AppRuleConfigTimeout)
}
