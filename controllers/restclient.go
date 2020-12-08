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
	log.Info("send request to mep method" + r.url)

	request, err := createRequest(r.url, r.method, r.body)
	if err != nil {
		log.Info("error while creating request")
		return nil, err
	}

	response, err := util.DoRequest(request)
	if err != nil {
		log.Info("error from do request")
		return nil, err
	}

	log.Info("returning response")
	return response, nil
}

// Creates rest request based on method
func createRequest(url string, method string, body []byte) (*http.Request, error) {
	switch method {
	case "GET":
		return http.NewRequest("GET", url, nil)
	case "DELETE":
		return http.NewRequest("DELETE", url, nil)
	case "POST":
		return http.NewRequest("POST", url, bytes.NewBuffer(body))
	case "PUT":
		return http.NewRequest("PUT", url, bytes.NewBuffer(body))
	default:
		return nil, errors.New("unknown rest method")
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

// Parses response from mep
func parseResponse(httpResponse *http.Response) (*Response, error) {
	mepResponse, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	if httpResponse.StatusCode == http.StatusOK {
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
	}
	return nil, errors.New("error response from mep")
}
