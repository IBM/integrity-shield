#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SHELL=/bin/bash

# LOAD ENVIRNOMENT SETTINGS (must be done at first)
###########################
ifeq ($(ISHIELD_REPO_ROOT),)
$(error ISHIELD_REPO_ROOT is not set)
endif

ifeq ($(ISHIELD_NS),)
$(error ISHIELD_NS is not set)
endif

include  .env
export $(shell sed 's/=.*//' .env)

ifeq ($(ENV_CONFIG),)
$(error ENV_CONFIG is not set)
endif

include  $(ENV_CONFIG)
export $(shell sed 's/=.*//' $(ENV_CONFIG))

# LOG
log-server:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_server.sh
log-operator:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_operator.sh
log-observer:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_observer.sh
log-ac-server:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_ac.sh

# BUILD
build-images:
	bash $(ISHIELD_REPO_ROOT)/scripts/build_images.sh

# DEPLOY
deploy-op:
	cd $(SHIELD_OP_DIR) && make deploy IMG=$(OPERATOR_IMG):$(VERSION)

deploy-cr-gk:
	kubectl create -f $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_gk.yaml -n $(ISHIELD_NS)

deploy-cr-ac:
	kubectl create -f $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_ac.yaml -n $(ISHIELD_NS)

# UNDEPLOY
delete-op:
	cd $(SHIELD_OP_DIR) && make undeploy

delete-cr-gk:
	kubectl delete -f $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_gk.yaml -n $(ISHIELD_NS)

delete-cr-ac:
	kubectl delete -f $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_ac.yaml -n $(ISHIELD_NS)
