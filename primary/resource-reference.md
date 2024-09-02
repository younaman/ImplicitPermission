ClusterRoleBinding --> ClusterRole
ReplicaSet --> Pod
HorizontalPodAutoscaler --> Pods
Binding --> Pod
Pod --> Secret
CustomResourceDefinition --> CR
Deployment --> Pod
StatefulSet --> Pod
rolebindings --> Role
namespaces --> all Res in ns
Pod --> ConfigMap
VolumeAttachment --> PersistentVolume
ServiceAccount --> Secret
HorizontalPodAutoscaler --> Pod
ReplicationController --> Pod
Ingress --> Secret
MutatingWebhookConfiguration --> all Res
CronJob --> Job
Job --> Pod
ValidatingWebhookConfiguration --> all Res
PersistentVolumeClaim --> PersistentVolume
DaemonSet --> Pod
rolebindings --> ClusterRole
StatefulSet --> PersistentVolumeClaim
Ingress --> Service
nodes --> Pod
APIService --> Service
Pod --> Node
Pod --> PersistentVolumeClaim
Deployment --> ReplicaSet
