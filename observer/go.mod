module github.com/IBM/integrity-shield/observer

go 1.16

require (
	github.com/IBM/integrity-shield/integrity-shield-server v0.0.0-00010101000000-000000000000
	github.com/ghodss/yaml v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210820081408-1767e96c5fe2
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
)

replace (
	github.com/IBM/integrity-shield/admission-controller => ../admission-controller
	github.com/IBM/integrity-shield/integrity-shield-server => ../integrity-shield-server
	github.com/IBM/integrity-shield/observer => ./
	github.com/sigstore/k8s-manifest-sigstore => github.com/hirokuni-kitahara/k8s-manifest-sigstore v0.0.0-20210813083459-81a1dc9de4cd
	k8s.io/api => k8s.io/api v0.19.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.0
	k8s.io/client-go => k8s.io/client-go v0.19.0
	k8s.io/code-generator => k8s.io/code-generator v0.19.0
	// k8s.io/kubectl => k8s.io/kubectl v0.21.2
	k8s.io/kubectl => k8s.io/kubectl v0.19.0
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.8.3
)

replace github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309 // Required by Helm
