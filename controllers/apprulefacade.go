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

// AppRuleFacade Represents app rule config facade
type AppRuleFacade struct {
	appInstanceId string
	restClient    iRestClient
}

// Creates new app rule facade
func createAppRuleFacade(restClient *RestClient, appInstanceId string) *AppRuleFacade {
	return &AppRuleFacade{
		restClient:    restClient,
		appInstanceId: appInstanceId,
	}
}

// Sends app rule config request to mep
func (a *AppRuleFacade) handleAppRuleRequest() (*Response, error) {
	httpResponse, err := a.restClient.sendRequest()
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()

	response, err := parseResponse(httpResponse, a.appInstanceId)
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
		log.Info(util.AppRuleConfigFailed)
		response.code = util.InternalServerError
		return response, nil
	}

	log.Info("configuration is in progress, sending task query")
	restClient := CreateRestClient(util.CreateTaskQueryUrl(response.progressModel.TaskId), util.Get, nil)
	task := createTask(response.progressModel.TaskId, restClient, a.appInstanceId)
	return task.handleTaskQuery()
}

// Sends app rule get request to mep
func (a *AppRuleFacade) handleAppRuleGetRequest() (*Response, error) {
	httpResponse, err := a.restClient.sendRequest()
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()

	response, err := parseGetResponse(httpResponse, a.appInstanceId)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// Creates new rest client based on method
func createRestClient(url string, method string, rule *models.AppdRule) (*RestClient, error) {
	if method == util.Post || method == util.Put {
		appRuleConfigBytes, err := json.Marshal(rule)
		if err != nil {
			return nil, errors.New(util.MarshalAppRuleModelError)
		}
		return CreateRestClient(url, method, appRuleConfigBytes), nil
	} else if method == util.Get || method == util.Delete {
		return CreateRestClient(url, method, nil), nil
	}
	return nil, errors.New(util.UnknownRestMethod)
}
