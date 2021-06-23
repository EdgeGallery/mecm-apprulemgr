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
	"github.com/agiledragon/gomonkey"
	"github.com/astaxie/beego/orm"
	"github.com/stretchr/testify/assert"
	"os"
	"reflect"
	"testing"
)


func TestGetDbAdapterSuccess(t *testing.T) {
	patch1 := gomonkey.ApplyFunc(orm.RegisterDataBase, func(_, _, _ string, _ ...int) (error) {
		// do nothing
		return nil
	})
	defer patch1.Reset()

	patch2 := gomonkey.ApplyFunc(orm.RunSyncdb, func(_ string, _ bool, _ bool) (error) {
		// do nothing
		return nil
	})
	defer patch2.Reset()

	var c *PgDb
	patch3 := gomonkey.ApplyMethod(reflect.TypeOf(c), "InitOrmer", func(*PgDb) (error) {
		go func() {
			// do nothing
		}()
		return nil
	})
	defer patch3.Reset()

	os.Setenv("APPRULEMGR_DB_PASSWORD", "fe0Hmv%sbq")
	db := &PgDb{}
	err := db.InitDatabase()
	assert.Nil(t, err, "TestGetDbAdapterSuccess execution result")

}

