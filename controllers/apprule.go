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
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"mecm-apprulemgr/models"
	"mecm-apprulemgr/util"
	"net/http"
)

// Represents app rule config model
type AppruleConfig struct {
	restclient iRestClient
}

// Creates new app rule config
func createAppRuleConfig(restClient *RestClient) *AppruleConfig {
	return &AppruleConfig{
		restclient: restClient,
	}
}

// Sends app rule config request to mep
func (a *AppruleConfig) handleAppRuleRequest() (*Response, error) {
	httpResponse, err := a.restclient.sendRequest()
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
			log.Info("success from mep")
			return response, nil
		}

		log.Info("sending task query")
		restClient := CreateRestClient(util.CreateTaskQueryUrl(response.progressModel.TaskId), "GET", nil)
		taskInfo := createTaskInfo(response.progressModel.TaskId, restClient)
		return taskInfo.handleTaskQuery()
	}
	return response, nil
}

// Creates new rest client based on method
func createRestClient(url string, method string, rule *models.AppdRule) (*RestClient, error) {
	switch method {
	case "POST":
		appRuleConfigBytes, err := json.Marshal(rule)
		if err != nil {
			return nil, errors.New("failed to convert to appRule to bytes")
		}

		return CreateRestClient(url, method, appRuleConfigBytes), nil
	case "PUT":
		appRuleConfigBytes, err := json.Marshal(rule)
		if err != nil {
			return nil, errors.New("failed to convert to appRule to bytes")
		}

		return CreateRestClient(url, method, appRuleConfigBytes), nil
	case "GET":
		return CreateRestClient(url, method, nil), nil
	case "DELETE":
		return CreateRestClient(url, method, nil), nil
	default:
		return nil, errors.New("unknown rest method")
	}
}
