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

package main

import (
	"context"
	"flag"
	"os"
	"strings"

	"github.com/IBM/integrity-shield/admission-controller/pkg/config"
	"github.com/IBM/integrity-shield/admission-controller/pkg/shield"
	log "github.com/sirupsen/logrus"
	k8smnfutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"

	miprofile "github.com/IBM/integrity-shield/admission-controller/pkg/apis/manifestintegrityprofile/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const tlsDir = `/run/secrets/tls`
const podNamespaceEnvKey = "POD_NAMESPACE"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultManifestIntegrityConfigMapName = "k8s-manifest-integrity-config"
const useRemote = true

// +kubebuilder:webhook:path=/validate-resource,mutating=false,failurePolicy=ignore,sideEffects=NoneOnDryRun,groups=*,resources=*,verbs=create;update,versions=*,name=k8smanifest.sigstore.dev,admissionReviewVersions={v1,v1beta1}

type k8sManifestHandler struct {
	Client client.Client
}

type AccumulatedResult struct {
	Allow   bool
	Message string
}

func (h *k8sManifestHandler) Handle(ctx context.Context, req admission.Request) admission.Response {

	log.Info("[DEBUG] request: ", req.Kind, ", ", req.Name)

	// load constraints
	constraints, err := config.LoadConstraints()
	if err != nil {
		log.Errorf("failed to load manifest integrity config; %s", err.Error())
		return admission.Allowed("error but allow for development")
	}

	results := []shield.ResultFromRequestHandler{}

	for _, constraint := range constraints {

		//match check: kind, namespace
		isMatched := matchCheck(req, constraint.Match)
		if !isMatched {
			r := shield.ResultFromRequestHandler{
				Allow:   true,
				Message: "not protected",
			}
			results = append(results, r)
			continue
		}

		// pick parameters from constaint
		paramObj := config.GetParametersFromConstraint(constraint)

		// call request handler & receive result from request handler (allow, message)
		r := shield.RequestHandlerController(useRemote, req, paramObj)
		// r := shield.RequestHandler(req, paramObj)

		results = append(results, *r)
	}

	// accumulate results from constraints
	ar := getAccumulatedResult(results)

	// TODO: generate events

	// TODO: update status

	// return admission response
	if ar.Allow {
		return admission.Allowed(ar.Message)
	} else {
		return admission.Denied(ar.Message)
	}
}

func matchCheck(req admission.Request, match miprofile.MatchCondition) bool {
	// check if excludedNamespace
	for _, ens := range match.ExcludedNamespaces {
		if k8smnfutil.MatchPattern(ens, req.Namespace) {
			return false
		}
	}
	// check if matched kind/namespace
	ns_matched := false
	kind_matched := false
	if len(match.Namespaces) == 0 {
		ns_matched = true
	} else {
		// check if cluster scope
		if req.Namespace == "" {
			ns_matched = true
		}
		for _, ns := range match.Namespaces {
			if k8smnfutil.MatchPattern(ns, req.Namespace) {
				ns_matched = true
			}
		}
	}
	if len(match.Kinds) == 0 {
		kind_matched = true
	} else {
		for _, ns := range match.Kinds {
			if k8smnfutil.MatchPattern(ns, req.Kind.Kind) {
				kind_matched = true
			}
		}
	}
	if ns_matched && kind_matched {
		return true
	}
	return false
}

func getAccumulatedResult(results []shield.ResultFromRequestHandler) *AccumulatedResult {
	deny_messages := []string{}
	accumulatedRes := &AccumulatedResult{}
	for _, result := range results {
		if !result.Allow {
			accumulatedRes.Allow = false
			accumulatedRes.Message = result.Message
			deny_messages = append(deny_messages, result.Message)
		}
	}
	if len(deny_messages) != 0 {
		accumulatedRes.Allow = false
		accumulatedRes.Message = strings.Join(deny_messages, ";")
		return accumulatedRes
	}
	accumulatedRes.Allow = true
	return accumulatedRes
}

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = corev1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "22a603b9.sigstore.dev",
		CertDir:            tlsDir,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-resource", &webhook.Admission{Handler: &k8sManifestHandler{Client: mgr.GetClient()}})

	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
