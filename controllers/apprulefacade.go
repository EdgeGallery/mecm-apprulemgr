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

// Represents app rule config facade
type AppRuleFacade struct {
	restClient iRestClient
}

// Creates new app rule facade
func createAppRuleFacade(restClient *RestClient) *AppRuleFacade {
	return &AppRuleFacade{
		restClient: restClient,
	}
}

// Sends app rule config request to mep
func (a *AppRuleFacade) handleAppRuleRequest() (*Response, error) {
	httpResponse, err := a.restClient.sendRequest()
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()

	response, err := parseResponse(httpResponse)
	if err != nil {
		return nil, err
	}

	if response.code == http.StatusAccepted {
		if response.progressModel.ConfigResult == util.Success {
			log.Info(util.AppRuleConfigSuccess)
			return response, nil
		} else if response.progressModel.ConfigResult == util.Failure {
			log.Info(util.AppRuleConfigFailed)
			return createFailureResponse(http.StatusInternalServerError, util.CreateOperationFailureModel(response.
				progressModel)), nil
		}

		log.Info("Configuration is in progress, sending task query")
		restClient := CreateRestClient(util.CreateTaskQueryUrl(response.progressModel.TaskId), util.Get, nil)
		taskInfo := createTaskInfo(response.progressModel.TaskId, restClient)
		return taskInfo.handleTaskQuery()
	}
	return response, nil
}

// Creates new rest client based on method
func createRestClient(url string, method string, rule *models.AppdRule) (*RestClient, error) {
	switch method {
	case util.Post:
		appRuleConfigBytes, err := json.Marshal(rule)
		if err != nil {
			return nil, errors.New(util.MarshaAppRuleModelError)
		}

		return CreateRestClient(url, method, appRuleConfigBytes), nil
	case util.Put:
		appRuleConfigBytes, err := json.Marshal(rule)
		if err != nil {
			return nil, errors.New(util.MarshaAppRuleModelError)
		}

		return CreateRestClient(url, method, appRuleConfigBytes), nil
	case util.Get:
		return CreateRestClient(url, method, nil), nil
	case util.Delete:
		return CreateRestClient(url, method, nil), nil
	default:
		return nil, errors.New(util.UnknownRestMethod)
	}
}
