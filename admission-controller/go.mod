module github.com/IBM/integrity-shield/admission-controller

go 1.16

require (
	github.com/IBM/integrity-shield/integrity-shield-server v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/jinzhu/copier v0.3.2
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210712080549-eac5e6aa7d2f
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-shield/admission-controller => ./
	github.com/IBM/integrity-shield/integrity-shield-server => ../integrity-shield-server
	github.com/sigstore/cosign => github.com/sigstore/cosign v0.4.1-0.20210602105506-5cb21aa7fbf9
	k8s.io/api => k8s.io/api v0.19.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/apiserver => k8s.io/apiserver v0.19.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0
	k8s.io/client-go => k8s.io/client-go v0.19.0
	k8s.io/code-generator => k8s.io/code-generator v0.19.0
	k8s.io/kubectl => k8s.io/kubectl v0.19.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.8.3
)
