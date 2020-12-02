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

package main

import (
	"github.com/astaxie/beego"
	log "github.com/sirupsen/logrus"
	"mecm-apprulemgr/controllers"
	"mecm-apprulemgr/util"
)

// Start application rule manager application
func main() {
	tlsConf, err := util.TLSConfig("HTTPSCertFile")
	if err != nil {
		log.Error("failed to config tls for beego")
		return
	}

	beego.BeeApp.Server.TLSConfig = tlsConf
	beego.ErrorController(&controllers.ErrorController{})
	beego.Run()
}
