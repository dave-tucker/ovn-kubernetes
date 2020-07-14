package node

import kapi "k8s.io/api/core/v1"

type nodePortWatcher interface{
	AddService(kapi.Service) error
	DeleteService(kapi.Service) error
	SyncServices([]kapi.Service) error
}