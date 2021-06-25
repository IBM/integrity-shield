module github.com/IBM/integrity-shield/admission-controller

go 1.16

require (
	github.com/fatih/color v1.12.0 // indirect
	github.com/jinzhu/copier v0.3.2
	github.com/onsi/ginkgo v1.16.4 // indirect
	github.com/onsi/gomega v1.13.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/sigstore/cosign v0.4.1-0.20210602105506-5cb21aa7fbf9 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/yuji-watanabe-jp/k8s-manifest-sigstore v0.0.0-20210617041144-9d27c6cc6d34
	golang.org/x/tools v0.1.2 // indirect
	k8s.io/api v0.21.1
	k8s.io/apiextensions-apiserver v0.21.1 // indirect
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/IBM/integrity-shield/admission-controller => ./
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
