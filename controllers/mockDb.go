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
	"github.com/astaxie/beego/orm"
	log "github.com/sirupsen/logrus"
)

type MockDb struct {
}

func (db *MockDb) InitDatabase() error {
	log.Info("DB adapter is not implemented")
	return nil
}

func (db *MockDb) InsertOrUpdateData(data interface{}, cols ...string) (err error) {
	return nil
}

func (db *MockDb) ReadData(data interface{}, cols ...string) (err error) {
	return nil
}

func (db *MockDb) DeleteData(data interface{}, cols ...string) (err error) {
	return nil
}

// return a raw query setter for raw sql string.
func (db *MockDb) QueryTable(tableName string) orm.QuerySeter {
	return nil
}

// Load Related
func (db *MockDb) LoadRelated(md interface{}, name string) (int64, error) {
	return 0, nil
}