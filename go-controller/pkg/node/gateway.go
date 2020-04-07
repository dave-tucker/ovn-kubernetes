package node

import kapi "k8s.io/api/core/v1"

type NodePortWatcher interface {
	AddService(service *kapi.Service) error
	DeleteService(service *kapi.Service) error
}
