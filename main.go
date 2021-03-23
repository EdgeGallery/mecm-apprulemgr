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
	"github.com/astaxie/beego/context"
	"github.com/astaxie/beego/plugins/cors"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	_ "mecm-apprulemgr/config"
	"mecm-apprulemgr/controllers"
	_ "mecm-apprulemgr/controllers"
	_ "mecm-apprulemgr/models"
	_ "mecm-apprulemgr/routers"
	"mecm-apprulemgr/util"
	"net/http"
)

// Start application rule manager application
func main() {
	r := &util.RateLimiter{}
	rate, err := limiter.NewRateFromFormatted("200-S")
	r.GeneralLimiter = limiter.New(memory.NewStore(), rate)

	beego.InsertFilter("/*", beego.BeforeRouter, func(c *context.Context) {
		util.RateLimit(r, c)
	}, true)

	beego.InsertFilter("*", beego.BeforeRouter,cors.Allow(&cors.Options{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"PUT", "PATCH", "POST", "GET", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "X-Requested-With", "Content-Type", "Accept"},
		ExposeHeaders: []string{"Content-Length"},
		AllowCredentials: true,
	}))

	beego.ErrorHandler("429", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("Too Many Requests"))
		return
	})

	tlsConf, err := util.TLSConfig("HTTPSCertFile")
	if err != nil {
		log.Error("failed to config tls for beego")
		return
	}

	beego.BeeApp.Server.TLSConfig = tlsConf
	beego.ErrorController(&controllers.ErrorController{})
	beego.Run()
}
