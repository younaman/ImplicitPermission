Q:

As a Kubernetes expert, your current task is to conduct a subresource permission reference analysis, which is defined as follow: In the context of Kubernetes, subresource permission reference analysis can be understood as analyzing how operations on subresources might affect other API resources or trigger operations on other API resources.
Below are some examples:
1. For pod/exec, creating pods/exec can access the terminal session of a pod and access the contents of secrets mounted in the pod. Therefore, it can be concluded: create pods/exec --> get secrets.
2. For pods/eviction, creating pods/eviction can delete the specified pod. Therefore, it can be concluded: create pods/eviction --> delete pod.
3. For replicasets/scale, patching or updating replicasets/scale can adjust the number of Pods managed by the ReplicaSets, thereby increasing or decreasing the number of Pod resources. Therefore, it can be concluded: patch/update replicasets/scale --> create/delete Pod.
4. For deployments/scale, patching or updating deployments/scale can adjust the number of Pods managed by the Deployments, thereby increasing or decreasing the number of Pod resources. Therefore, it can be concluded: patch/update deployments/scale --> create/delete Pod.
5. For statefulsets/scale, patching or updating statefulsets/scale can adjust the number of Pods managed by the StatefulSets, thereby increasing or decreasing the number of Pod resources. Therefore, it can be concluded: patch/update statefulsets/scale --> create/delete Pod.

Do you understand the above concepts, and are you ready to start the analysis? Answer yes or no.

A:
Yes
-------------------------------------
Q：
The verbs supported by replicationcontrollers/scale resource include: [get, patch, update]
Based on the verb obtained above, analyze the subresource reference of replicationcontrollers/scale, and examine its potential impact on other resources. Please note that the result should be in the following format: "A --> B", where A is verb + replicationcontrollers/scale, B is verb + other resources.

A：
Given the verbs available for the `replicationcontrollers/scale` subresource in Kubernetes (`get`, `patch`, `update`), we can analyze how operations on this subresource might affect other resources. The primary purpose of the `scale` subresource is to manage the replica count of the pods that are controlled by the replication controller. Here's the analysis:

1. **Get replicationcontrollers/scale**: This operation retrieves the current scale of the replication controller, specifically the number of replicas. It does not directly affect other resources, so no direct action on other resources is implied.

2. **Patch replicationcontrollers/scale**: Patching the `replicationcontrollers/scale` subresource involves modifying the number of replicas. This directly affects the pods managed by the replication controller.
   
   - **patch replicationcontrollers/scale --> create/delete pod**: Increasing the replica count results in the creation of new pods, whereas decreasing the replica count leads to the deletion of existing pods.

3. **Update replicationcontrollers/scale**: Similar to patching, updating this subresource changes the number of replicas.
   
   - **update replicationcontrollers/scale --> create/delete pod**: This operation similarly leads to either the creation or deletion of pods depending on whether the replica count is increased or decreased.

The focus here is on how changing the scale affects pod resources directly under the management of the specified replication controller.