#!/bin/sh
# Copyright 2020 Huawei Technologies Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# validates whether file exist
validate_file_exists() {
  file_path="$1"

  # checks variable is unset
  if [ -z "$file_path" ]; then
    echo "file path variable is not set"
    return 1
  fi

  # checks if file exists
  if [ ! -f "$file_path" ]; then
    echo "file does not exist"
    return 1
  fi

  return 0
}

# ssl parameters validation
validate_file_exists "/usr/app/ssl/server_tls.crt"
valid_server_certificate="$?"
if [ ! "$valid_server_certificate" -eq "0" ]; then
  echo "server certificate is missing"
  exit 1
fi

validate_file_exists "/usr/app/ssl/server_tls.key"
valid_server_certificate="$?"
if [ ! "$valid_server_certificate" -eq "0" ]; then
  echo "server key is missing"
  exit 1
fi

validate_file_exists "/usr/app/ssl/ca.crt"
valid_server_certificate="$?"
if [ ! "$valid_server_certificate" -eq "0" ]; then
  echo "ca cert is missing"
  exit 1
fi

sed -i "s/^HTTPSAddr.*=.*$/HTTPSAddr = $(hostname -i)/g" conf/app.conf

cd /usr/app
umask 0027
$HOME/bin/apprulemgr