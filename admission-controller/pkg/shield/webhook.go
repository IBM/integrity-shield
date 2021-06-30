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
	"context"
	"os"
	"strconv"
	"strings"

	miprofile "github.com/IBM/integrity-shield/admission-controller/pkg/apis/manifestintegrityprofile/v1alpha1"
	mipclient "github.com/IBM/integrity-shield/admission-controller/pkg/client/manifestintegrityprofile/clientset/versioned/typed/manifestintegrityprofile/v1alpha1"
	k8smnfconfig "github.com/IBM/integrity-shield/admission-controller/pkg/config"
	"github.com/IBM/integrity-shield/admission-controller/pkg/handler"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type AccumulatedResult struct {
	Allow   bool
	Message string
}

func ProcessRequest(req admission.Request) admission.Response {
	// load constraints
	constraints, err := LoadConstraints()
	if err != nil {
		log.Errorf("failed to load manifest integrity config; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	results := []handler.ResultFromRequestHandler{}

	for _, constraint := range constraints {

		//match check: kind, namespace
		isMatched := matchCheck(req, constraint.Match)
		if !isMatched {
			r := handler.ResultFromRequestHandler{
				Allow:   true,
				Message: "not protected",
			}
			results = append(results, r)
			continue
		}

		// pick parameters from constaint
		paramObj := GetParametersFromConstraint(constraint)

		// call request handler & receive result from request handler (allow, message)
		useRemote, _ := strconv.ParseBool(os.Getenv("USE_REMOTE_HANDLER"))
		r := handler.RequestHandlerController(useRemote, req, paramObj)
		// r := handler.RequestHandler(req, paramObj)

		results = append(results, *r)
	}

	// accumulate results from constraints
	ar := getAccumulatedResult(results)

	// TODO: generate events

	// TODO: update status

	// return admission response
	log.Info("[DEBUG] process result: ", ar.Allow, ", ", ar.Message)
	if ar.Allow {
		return admission.Allowed(ar.Message)
	} else {
		return admission.Denied(ar.Message)
	}
}

func GetParametersFromConstraint(constraint miprofile.ManifestIntegrityProfileSpec) *k8smnfconfig.ParameterObject {
	return &constraint.Parameters
}

func LoadConstraints() ([]miprofile.ManifestIntegrityProfileSpec, error) {
	constraints, err := loadManifestIntegiryProfiles()
	if err != nil {
		return []miprofile.ManifestIntegrityProfileSpec{}, err
	}
	if constraints == nil {
		return []miprofile.ManifestIntegrityProfileSpec{}, nil
	}
	return constraints, nil
}

func loadManifestIntegiryProfiles() ([]miprofile.ManifestIntegrityProfileSpec, error) {
	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := mipclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, nil
	}
	miplist, err := clientset.ManifestIntegrityProfiles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Error("failed to get ManifestIntegrityProfiles:", err.Error())
		return nil, nil
	}
	var constraints []miprofile.ManifestIntegrityProfileSpec
	for _, mip := range miplist.Items {
		constraints = append(constraints, mip.Spec)
	}
	return constraints, nil
}

func matchCheck(req admission.Request, match miprofile.MatchCondition) bool {
	// check if excludedNamespace
	for _, ens := range match.ExcludedNamespaces {
		if k8smnfutil.MatchPattern(ens, req.Namespace) {
			return false
		}
	}
	// check if matched kind/namespace
	nsMatched := false
	kindMatched := false
	if len(match.Namespaces) == 0 {
		nsMatched = true
	} else {
		// check if cluster scope
		if req.Namespace == "" {
			nsMatched = true
		}
		for _, ns := range match.Namespaces {
			if k8smnfutil.MatchPattern(ns, req.Namespace) {
				nsMatched = true
			}
		}
	}
	if len(match.Kinds) == 0 {
		kindMatched = true
	} else {
		for _, ns := range match.Kinds {
			if k8smnfutil.MatchPattern(ns, req.Kind.Kind) {
				kindMatched = true
			}
		}
	}
	if nsMatched && kindMatched {
		return true
	}
	return false
}

func getAccumulatedResult(results []handler.ResultFromRequestHandler) *AccumulatedResult {
	denyMessages := []string{}
	allowMessages := []string{}
	accumulatedRes := &AccumulatedResult{}
	for _, result := range results {
		if !result.Allow {
			accumulatedRes.Message = result.Message
			denyMessages = append(denyMessages, result.Message)
		} else {
			allowMessages = append(allowMessages, result.Message)
		}
	}
	if len(denyMessages) != 0 {
		accumulatedRes.Allow = false
		accumulatedRes.Message = strings.Join(denyMessages, ";")
		return accumulatedRes
	}
	accumulatedRes.Allow = true
	accumulatedRes.Message = strings.Join(allowMessages, ";")
	return accumulatedRes
}
