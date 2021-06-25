//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package shield

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	miprofile "github.com/IBM/integrity-shield/admission-controller/pkg/apis/manifestintegrityprofile/v1alpha1"
	k8smnfconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	log "github.com/sirupsen/logrus"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const remoteRequestHandlerURL = "https://integrity-shield-api.k8s-manifest-sigstore.svc:8123/api/request"

func RequestHandlerController(remote bool, req admission.Request, paramObj *miprofile.ParameterObject) *ResultFromRequestHandler {
	r := &ResultFromRequestHandler{}
	if remote {
		log.Info("[DEBUG] remote request handler ", remoteRequestHandlerURL)
		// http call to remote request handler service
		input := &RemoteRequestHandlerInputMap{
			Request:   req,
			Parameter: *paramObj,
		}

		inputjson, _ := json.Marshal(input)
		transCfg := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: transCfg}
		res, err := client.Post(remoteRequestHandlerURL, "application/json", bytes.NewBuffer([]byte(inputjson)))
		if err != nil {
			log.Error("Error reported from Remote RequestHandler", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		if res.StatusCode != 200 {
			log.Error("Error reported from Remote RequestHandler: statusCode is not 200")
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Error("error: fail to read body: ", err)
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		err = json.Unmarshal([]byte(string(body)), &r)
		if err != nil {
			log.Error("error: fail to Unmarshal: ", err)
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		log.Info("[DEBUG] Response from remote request handler ", r)
		return r
	} else {
		// local request handler
		r = RequestHandler(req, paramObj)
	}
	return r
}

func RequestHandler(req admission.Request, paramObj *miprofile.ParameterObject) *ResultFromRequestHandler {
	// unmarshal admission request object
	// load Resource from Admission request
	var resource unstructured.Unstructured
	objectBytes := req.AdmissionRequest.Object.Raw
	err := json.Unmarshal(objectBytes, &resource)
	if err != nil {
		log.Errorf("failed to Unmarshal a requested object into %T; %s", resource, err.Error())
		return &ResultFromRequestHandler{
			Allow:   true,
			Message: "error but allow for development",
		}
	}

	// TODO: load shield config
	_ = loadShieldConfig()

	// TODO: Proccess with parameter
	//filter by user
	skipUserMatched := paramObj.SkipUsers.Match(resource, req.AdmissionRequest.UserInfo.Username)

	//check scope
	inScopeObjMatched := paramObj.InScopeObjects.Match(resource)

	//operation check
	isUpdateRequest := isUpdateRequest(req.AdmissionRequest.Operation)

	allow := true
	message := ""
	if skipUserMatched {
		allow = true
		message = "ignore user config matched"
	} else if !inScopeObjMatched {
		allow = true
		message = "this resource is not in scope of verification"
	} else {
		// get verifyOption and imageRef from Parameter
		imageRef := paramObj.ImageRef
		// prepare local key for verifyResource
		keyPath := ""
		if paramObj.KeySecertName != "" {
			keyPath, _ = k8smnfconfig.LoadKeySecret(paramObj.KeySecertNamespace, paramObj.KeySecertName)
		}
		vo := &(paramObj.VerifyOption)
		// call VerifyResource with resource, verifyOption, keypath, imageRef
		result, err := k8smanifest.VerifyResource(resource, imageRef, keyPath, vo)
		if err != nil {
			log.Errorf("failed to check a requested resource; %s", err.Error())
			return &ResultFromRequestHandler{
				Allow:   true,
				Message: "error but allow for development",
			}
		}
		if result.InScope {
			if result.Verified {
				allow = true
				message = fmt.Sprintf("singed by a valid signer: %s", result.Signer)
			} else {
				allow = false
				message = "no signature found"
				if result.Diff != nil && result.Diff.Size() > 0 {
					message = fmt.Sprintf("diff found: %s", result.Diff.String())
				}
				if result.Signer != "" {
					message = fmt.Sprintf("signer config not matched, this is signed by %s", result.Signer)
				}
			}
			if isUpdateRequest {
				// TODO: mutation check for update request
				isMutated := checkIgnoreFields(result.Diff, paramObj.IgnoreFields)
				if !isMutated {
					allow = true
					message = "no mutation found"
				}
			}
		} else {
			allow = true
			message = "not protected"
		}
	}

	r := &ResultFromRequestHandler{
		Allow:   allow,
		Message: message,
	}

	// log
	log.Info("[DEBUG] result:", r.Message)

	return r
}

type ResultFromRequestHandler struct {
	Allow   bool
	Message string
}

type IshieldConfig struct {
	IshieldConfig string
}

func loadShieldConfig() IshieldConfig {
	return IshieldConfig{}
}

func isUpdateRequest(operation v1.Operation) bool {
	return (operation == v1.Update)
}

func checkIgnoreFields(diff *mapnode.DiffResult, ignoreFields k8smanifest.ObjectFieldBindingList) bool {
	return true
}

type RemoteRequestHandlerInputMap struct {
	Request   admission.Request         `json:"request,omitempty"`
	Parameter miprofile.ParameterObject `json:"parameters,omitempty"`
}