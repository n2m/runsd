// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"strings"
)

func identityToken(audience string) (string, error) {
	if v := os.Getenv("CLOUD_RUN_ID_TOKEN"); v != "" {
		return strings.TrimSpace(v), nil
	}
	return identityTokenFromMetadata(audience)
}

func identityTokenFromMetadata(audience string) (string, error) {
	var (
		token = getToken(audience)
		err   error
	)

	if token == "" {
		token, err = queryMetadata("http://metadata.google.internal./computeMetadata/v1/instance/service-accounts/default/identity?audience=" + audience)
		setToken(audience, token)
	}

	return token, err
}
