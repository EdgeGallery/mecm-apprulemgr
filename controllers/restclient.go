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
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"mecm-apprulemgr/models"
	"mecm-apprulemgr/util"
	"net/http"
)

type iRestClient interface {
	sendRequest() (*http.Response, error)
}

// RestClient Represents RestClient model
type RestClient struct {
	url    string
	method string
	body   []byte
}

// CreateRestClient Creates new rest client
func CreateRestClient(url string, method string, body []byte) *RestClient {
	return &RestClient{
		url:    url,
		method: method,
		body:   body,
	}
}

// Sends rest request and returns response
func (r *RestClient) sendRequest() (*http.Response, error) {
	request, err := createRequest(r.url, r.method, r.body)
	if err != nil {
		log.Error("failed to create request")
		return nil, err
	}

	response, err := util.DoRequest(request)
	if err != nil {
		log.Error("failed to send request")
		return nil, err
	}

	log.Info("mep response code " + response.Status)
	return response, nil
}

// Creates rest request based on method
func createRequest(url string, method string, body []byte) (*http.Request, error) {
	switch method {
	case util.Get:
		return http.NewRequest(util.Get, url, nil)
	case util.Delete:
		return http.NewRequest(util.Delete, url, nil)
	case util.Post:
		return http.NewRequest(util.Post, url, bytes.NewBuffer(body))
	case util.Put:
		return http.NewRequest(util.Put, url, bytes.NewBuffer(body))
	default:
		return nil, errors.New(util.UnknownRestMethod)
	}
}

// Response Represents response model
type Response struct {
	code          int
	progressModel *models.OperationProgressModel
	appdrule      *models.AppdRule
}

// Creates new progress response model
func createResponse(httpStatusCode int, operationProgressModel *models.OperationProgressModel) *Response {
	return &Response{
		code:          httpStatusCode,
		progressModel: operationProgressModel,
	}
}

// Creates new get request response model
func createGetResponse(httpStatusCode int, appdRule *models.AppdRule) *Response {
	return &Response{
		code:     httpStatusCode,
		appdrule: appdRule,
	}
}

// Parses response from mep
func parseResponse(httpResponse *http.Response, appInstanceId string) (*Response, error) {
	mepResponse, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Error("failed to read mep response body")
		return nil, err
	}

	if httpResponse.StatusCode == http.StatusOK {
		var operationProgressModel *models.OperationProgressModel
		if err = json.Unmarshal(mepResponse, &operationProgressModel); err != nil {
			log.Error("failed to unmarshal")
			return nil, err
		}
		return createResponse(httpResponse.StatusCode, operationProgressModel), nil
	}

	var operationFailureModel *models.OperationFailureModel
	if err = json.Unmarshal(mepResponse, &operationFailureModel); err != nil {
		log.Error("failed to unmarshal")
		return nil, err
	}
	return createResponse(httpResponse.StatusCode,
		util.CreateOperationProgressModel(appInstanceId, util.Failure, operationFailureModel.Detail)), nil
}

// Parses get response from mep
func parseGetResponse(httpResponse *http.Response, appInstanceId string) (*Response, error) {
	mepResponse, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		log.Error("failed to read mep response body")
		return nil, err
	}

	if httpResponse.StatusCode == http.StatusOK {
		var appRuleModel *models.AppdRule
		if err = json.Unmarshal(mepResponse, &appRuleModel); err != nil {
			log.Error("failed to unmarshal")
			return nil, err
		}
		return createGetResponse(httpResponse.StatusCode, appRuleModel), nil
	}

	var operationFailureModel *models.OperationFailureModel
	if err = json.Unmarshal(mepResponse, &operationFailureModel); err != nil {
		log.Error("failed to unmarshal")
		return nil, err
	}
	return createResponse(httpResponse.StatusCode, util.CreateOperationProgressModel(appInstanceId,
		util.Failure, operationFailureModel.Detail)), nil
}
