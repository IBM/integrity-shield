package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const timeFormat = "2006-01-02 15:04:05"

const defaultConfigKeyInConfigMap = "config.yaml"
const defaultPodNamespace = "k8s-manifest-sigstore"
const defaultTargetResourceConfigName = "target-resource-config"
const logLevelEnvKey = "LOG_LEVEL"
const k8sLogLevelEnvKey = "K8S_MANIFEST_SIGSTORE_LOG_LEVEL"

const ImageRefAnnotationKey = "cosign.sigstore.dev/imageRef"

type Inspector struct {
	APIResources []groupResource

	dynamicClient dynamic.Interface
}

type Result struct {
	Summary     string         `json:"summary"`
	Details     []ResultDetail `json:"details"`
	LastUpdated string         `json:"lastUpdated"`
}

type ResultDetail struct {
	Resource    unstructured.Unstructured `json:"resource"`
	Result      string                    `json:"result"`
	Verified    bool                      `json:"verified"`
	Provenances []*k8smnfutil.Provenance  `json:"provenances"`
}

type groupResourceWithTargetNS struct {
	groupResource    `json:""`
	TargetNamespaces []string `json:"targetNamespace"`
}

// groupResource contains the APIGroup and APIResource
type groupResource struct {
	APIGroup    string             `json:"apiGroup"`
	APIVersion  string             `json:"apiVersion"`
	APIResource metav1.APIResource `json:"resource"`
}

type TargetResourceConfig struct {
	TargetResources []groupResourceWithTargetNS        `json:"targetResouces"`
	IgnoreFields    k8smanifest.ObjectFieldBindingList `json:"ignoreFields,omitempty"`
	KeyConfigs      []KeyConfig                        `json:"keyConfigs"`
}

type KeyConfig struct {
	KeySecretName      string `json:"keySecretName"`
	KeySecertNamespace string `json:"keySecretNamespace"`
}

var logLevelMap = map[string]log.Level{
	"panic": log.PanicLevel,
	"fatal": log.FatalLevel,
	"error": log.ErrorLevel,
	"warn":  log.WarnLevel,
	"info":  log.InfoLevel,
	"debug": log.DebugLevel,
	"trace": log.TraceLevel,
}

func NewInspector() *Inspector {
	insp := &Inspector{}
	return insp
}

func (self *Inspector) Init() error {
	log.Info("init Inspector....")
	kubeconf, _ := kubeutil.GetKubeConfig()

	var err error

	err = self.getAPIResources(kubeconf)
	if err != nil {
		return err
	}

	dynamicClient, err := dynamic.NewForConfig(kubeconf)
	if err != nil {
		return err
	}
	self.dynamicClient = dynamicClient

	// log
	if os.Getenv("LOG_FORMAT") == "json" {
		log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	}
	logLevelStr := os.Getenv(logLevelEnvKey)
	if logLevelStr == "" {
		logLevelStr = "info"
	}
	logLevel, ok := logLevelMap[logLevelStr]
	if !ok {
		logLevel = log.InfoLevel
	}
	os.Setenv(k8sLogLevelEnvKey, logLevelStr)
	log.SetLevel(logLevel)
	return nil
}

func (self *Inspector) Run() {
	// load configmap
	tconfig, err := loadTargetResourceConfig()
	narrowedGVKList := tconfig.TargetResources
	ignoreFields := tconfig.IgnoreFields
	secrets := tconfig.KeyConfigs
	if err != nil {
		fmt.Println("Failed to load TargetResourceConfig; err: ", err.Error())
	}
	// get all resources of extracted GVKs
	resources := []unstructured.Unstructured{}
	for _, gResource := range narrowedGVKList {
		tmpResources, _ := self.getAllResoucesByGroupResource(gResource)
		resources = append(resources, tmpResources...)
	}

	results := []ResultDetail{}
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
			results = append(results, ResultDetail{
				Resource: resource,
				Result:   "no signature found",
				Verified: false,
			})
			continue
		}
		// secret
		log.Debug("secrets", secrets)
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
		results = append(results, ResultDetail{
			Resource:    resource,
			Result:      resultMsg,
			Verified:    verified,
			Provenances: result.Provenances,
		})
	}
	// log
	fmt.Println("\nObservation time", time.Now().Format(timeFormat))
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w, "Verified\tNamespace\tKind\tName\tMessage\t")
	for _, res := range results {
		resStr := strconv.FormatBool(res.Verified) + "\t" + res.Resource.GetNamespace() + "\t" + res.Resource.GetKind() + "\t" + res.Resource.GetName() + "\t" + res.Result + "\t"
		fmt.Fprintln(w, resStr)
	}
	w.Flush()
	// provenances log

	for _, res := range results {
		if len(res.Provenances) != 0 {
			fmt.Println("\nProvenance result for", res.Resource.GetNamespace(), res.Resource.GetKind(), res.Resource.GetName())
			var resultBytes []byte
			for _, pr := range res.Provenances {
				resultBytes, _ = json.MarshalIndent(pr, "", "    ")
				fmt.Println(string(resultBytes))
			}
		}
	}
	w.Flush()
	return
}

func (self *Inspector) getAPIResources(kubeconfig *rest.Config) error {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(kubeconfig)
	if err != nil {
		return err
	}

	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return err
	}

	resources := []groupResource{}
	for _, apiResourceList := range apiResourceLists {
		if len(apiResourceList.APIResources) == 0 {
			continue
		}
		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			continue
		}
		for _, resource := range apiResourceList.APIResources {
			if len(resource.Verbs) == 0 {
				continue
			}
			resources = append(resources, groupResource{
				APIGroup:    gv.Group,
				APIVersion:  gv.Version,
				APIResource: resource,
			})
		}
	}
	self.APIResources = resources
	return nil
}

func (self *Inspector) getAllResoucesByGroupResource(gResourceWithTargetNS groupResourceWithTargetNS) ([]unstructured.Unstructured, error) {
	var resources []unstructured.Unstructured
	var err error
	var gResource groupResource
	gResource = gResourceWithTargetNS.groupResource
	targetNSs := gResourceWithTargetNS.TargetNamespaces
	namespaced := gResource.APIResource.Namespaced
	gvr := schema.GroupVersionResource{
		Group:    gResource.APIGroup,
		Version:  gResource.APIVersion,
		Resource: gResource.APIResource.Name,
	}

	var tmpResourceList *unstructured.UnstructuredList
	if namespaced {
		for _, ns := range targetNSs {
			tmpResourceList, err = self.dynamicClient.Resource(gvr).Namespace(ns).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				break
			}
			resources = append(resources, tmpResourceList.Items...)
		}

	} else {
		tmpResourceList, err = self.dynamicClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
		resources = append(resources, tmpResourceList.Items...)
	}
	if err != nil {
		// ignore RBAC error - IShield SA
		fmt.Println("RBAC error when listing resources; error:", err.Error())
		return []unstructured.Unstructured{}, nil
	}
	return resources, nil
}

func convertGVKToGVR(gvk schema.GroupVersionKind, apiResouces []groupResource) schema.GroupVersionResource {
	found := schema.GroupVersionResource{}
	for _, gResource := range apiResouces {
		groupOk := (gResource.APIGroup == gvk.Group)
		versionOK := (gResource.APIVersion == gvk.Version)
		kindOk := (gResource.APIResource.Kind == gvk.Kind)
		if groupOk && versionOK && kindOk {
			found = schema.GroupVersionResource{
				Group:    gvk.Group,
				Version:  gvk.Version,
				Resource: gResource.APIResource.Name,
			}
			break
		}
	}
	return found
}

func loadTargetResourceConfig() (*TargetResourceConfig, error) {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = defaultPodNamespace
	}
	configName := os.Getenv("TARGET_RESOURCE_CONFIG_NAME")
	if configName == "" {
		configName = defaultTargetResourceConfigName
	}
	configKey := os.Getenv("CONFIG_KEY")
	if configKey == "" {
		configKey = defaultConfigKeyInConfigMap
	}

	config, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubeclient.NewForConfig(config)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", configName, namespace))
	}
	cfgBytes, found := cm.Data[configKey]
	if !found {
		return nil, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKey))
	}
	var tr *TargetResourceConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &tr)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", tr))
	}
	return tr, nil
}

func LoadKeySecret(keySecertNamespace, keySecertName string) (string, error) {
	obj, err := kubeutil.GetResource("v1", "Secret", keySecertNamespace, keySecertName)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var secret v1.Secret
	_ = json.Unmarshal(objBytes, &secret)
	keyDir := fmt.Sprintf("/tmp/%s/%s/", keySecertNamespace, keySecertName)
	log.Debug("keyDir", keyDir)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		os.MkdirAll(keyDir, os.ModePerm)
		fpath := filepath.Join(keyDir, fname)
		err = ioutil.WriteFile(fpath, keyData, 0644)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		keyPath = fpath
		break
	}
	if keyPath == "" && len(sumErr) > 0 {
		return "", errors.New(fmt.Sprintf("failed to save secret data as a file; %s", strings.Join(sumErr, "; ")))
	}
	if keyPath == "" {
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", keySecertName, keySecertNamespace))
	}

	return keyPath, nil
}
