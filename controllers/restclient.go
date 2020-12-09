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

// Represents Restclient model
type RestClient struct {
	url    string
	method string
	body   []byte
}

// Creates new rest client
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
		return nil, err
	}

	response, err := util.DoRequest(request)
	if err != nil {
		return nil, err
	}

	log.Info("returning response")
	return response, nil
}

// Creates rest request based on method
func createRequest(url string, method string, body []byte) (*http.Request, error) {
	switch method {
	case util.Get:
		return http.NewRequest(method, url, nil)
	case util.Delete:
		return http.NewRequest(method, url, nil)
	case util.Post:
		return http.NewRequest(method, url, bytes.NewBuffer(body))
	case util.Put:
		return http.NewRequest(method, url, bytes.NewBuffer(body))
	default:
		return nil, errors.New(util.UnknownRestMethod)
	}
}

// Represents response model
type Response struct {
	code          int
	failureModel  *models.OperationFailureModel
	progressModel *models.OperationProgressModel
}

// Creates new progress response model
func createProgressResponse(httpStatusCode int, operationProgressModel *models.OperationProgressModel) *Response {
	return &Response{
		code:          httpStatusCode,
		progressModel: operationProgressModel,
	}
}

// Creates new failure response model
func createFailureResponse(httpStatusCode int, operationFailureModel *models.OperationFailureModel) *Response {
	return &Response{
		code:         httpStatusCode,
		failureModel: operationFailureModel,
	}
}

// Parses response from mep
func parseResponse(httpResponse *http.Response) (*Response, error) {
	mepResponse, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	if httpResponse.StatusCode == http.StatusOK || httpResponse.StatusCode == http.StatusAccepted {
		var operationProgressModel *models.OperationProgressModel
		if err = json.Unmarshal(mepResponse, &operationProgressModel); err != nil {
			return nil, err
		}

		return createProgressResponse(httpResponse.StatusCode, operationProgressModel), nil
	} else if httpResponse.StatusCode == http.StatusBadRequest ||
		httpResponse.StatusCode == http.StatusForbidden ||
		httpResponse.StatusCode == http.StatusNotFound {

		var operationFailureModel *models.OperationFailureModel
		if err = json.Unmarshal(mepResponse, &operationFailureModel); err != nil {
			return nil, err
		}

		return createFailureResponse(httpResponse.StatusCode, operationFailureModel), nil
	}

	log.Info("error response from mep, status code", httpResponse.StatusCode)
	return nil, errors.New(util.ErrorFromMep)
}
