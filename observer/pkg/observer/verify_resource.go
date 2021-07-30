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

package observer

import (
	"fmt"
	"strings"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func InspectResources(resources []unstructured.Unstructured, ignoreFields k8smanifest.ObjectFieldBindingList, secrets []KeyConfig) []VerifyResult {
	results := []VerifyResult{}
	for _, resource := range resources {
		log.Debug("Observed Resource:", resource.GetAPIVersion(), resource.GetKind(), resource.GetNamespace(), resource.GetName())
		vo := &k8smanifest.VerifyResourceOption{}
		vo.IgnoreFields = ignoreFields
		vo.CheckDryRunForApply = true
		vo.Provenance = true
		annotations := resource.GetAnnotations()
		annoImageRef, found := annotations[ImageRefAnnotationKey]
		if found {
			vo.ImageRef = annoImageRef
		} else {
			results = append(results, VerifyResult{
				Resource: resource,
				Result:   "no signature found",
				Verified: false,
			})
			continue
		}
		// secret
		for _, s := range secrets {
			if s.KeySecertNamespace == resource.GetNamespace() {
				pubkey, err := LoadKeySecret(s.KeySecertNamespace, s.KeySecretName)
				if err != nil {
					fmt.Println("Failed to load pubkey; err: ", err.Error())
				}
				vo.KeyPath = pubkey
				break
			}
		}
		log.Debug("VerifyResourceOption", vo)
		result, err := k8smanifest.VerifyResource(resource, vo)
		if err != nil {
			fmt.Println("Failed to verify resource; err: ", err.Error())
			continue
		}

		message := ""
		if result.InScope {
			if result.Verified {
				message = fmt.Sprintf("singed by a valid signer: %s", result.Signer)
			} else {
				message = "no signature found"
				if result.Diff != nil && result.Diff.Size() > 0 {
					message = fmt.Sprintf("diff found: %s", result.Diff.String())
				} else if result.Signer != "" {
					message = fmt.Sprintf("signer config not matched, this is signed by %s", result.Signer)
				}
			}
		} else {
			message = "not protected"
		}
		tmpMsg := strings.Split(message, " (Request: {")
		resultMsg := ""
		if len(tmpMsg) > 0 {
			resultMsg = tmpMsg[0]
		}
		verified := result.Verified
		results = append(results, VerifyResult{
			Resource:    resource,
			Result:      resultMsg,
			Verified:    verified,
			SigRef:      result.SigRef,
			Provenances: result.Provenances,
		})
	}
	return results
}