# ImplicitPermission Analysis

This is a toolkit for analyzing implicit permissions in kubernetes.

In  our approach, there are three parts, namely Resource Identification, Explicit Permission Analysis and Implicit Permission Analysis.

- Resource Identification: The tool performs static analysis on the Kubernetes source code, enabling the identification and collection of API resources within Kubernetes. The input to the tool is the Kubernetes source code, and the output is a list of API resources in Kubernetes.
- Explicit Permission Analysis: This tool performs static analysis on Kubernetes source code and, building on the functionality and logic of the previous tool, enables the collection of explicit permissions for API resources in Kubernetes. The input to the tool is the Kubernetes source code, and the output is a list of explicit permissions for API resources in Kubernetes.
- Combined LLM&Static permission analysis: In our combined analysis architecture, LLM-based reasoning and static analysis are executed in parallel. Each component independently analyzes the same set of explicit permissions and attempts to identify associated implicit permission paths.
  - For the LLM-based-analysis, we explore the logical reasoning capacities and the extensive pre-trained domain knowledge inherent in the large language model (i.e., GPT-4.5) to identify implicit permission references carried by explicit permissions. Take the explicit permissions analyzed in the second step as prompt input, and LLM will analyze the implicit permissions and output them as implicit permissions reference results. 
  - For the Static Analysis, static analysis is performed on the Kubernetes source code. By analyzing the controller control loops corresponding to the resources, the implicit permission impacts of the resources are identified. The input to the tool is the Kubernetes source code, and the output is a reference of implicit permissions.

# Resource Identification

Based on the initialization and registration characteristics of resources in kubernetes, this tool collects all resources in kubernetes through static analysis. Kubernetes resources are categorized into primary and sub-resources. More specifically:

- For primary resources, our key observation is that each primary resource registers a storage object before it is utilized. In Kubernetes, a storage object is a data structure responsible for managing the lifecycle of a resource. By focusing on the initialization and registration patterns of these storage objects, we can systematically uncover all primary resources.
- For sub-resources, our key observation is that the registration process of sub-resources is inherently linked to their corresponding primary resources. This connection provides a systematic method to trace and document all related sub-resources following the registration of the primary resource.

## Usage

### Local Environment

This section explains the steps to run the tool by compiling the source code. 

Environmental requirements are as follows:

- Linux
- go1.23.0

First, download the kubernetes source code to the local machine. 

``````bash
root@instance:/# git clone https://github.com/kubernetes/kubernetes.git /kubernetes
root@instance:/# cd /kubernetes
root@instance:/kubernetes# git checkout v1.30.10
``````

Second, Install dependencies for the tool. (We need to go to the folder corresponding to the tool. The folder is named *Resource_Identification_Analysis*.)

``````bash
root@instance:/# cd /ImplicitPermission/Resource_Identification_Analysis/main
root@instance:/ImplicitPermission/Resource_Identification_Analysis/main# go mod init ri
root@instance:/ImplicitPermission/Resource_Identification_Analysis/main# go mod tidy
``````

Then, run the tool.

```bash
root@instance:/ImplicitPermission/Resource_Identification_Analysis/main# chmod +x start.sh
root@instance:/ImplicitPermission/Resource_Identification_Analysis/main# ./start.sh
```

Or, We also provide a compiled binary file, which can be used for direct operation.

```bash
root@instance:/ImplicitPermission/Resource_Identification_Analysis/main# chmod +x start2.sh
root@instance:/ImplicitPermission/Resource_Identification_Analysis/main# ./start2.sh
```

### Docker Environment

We also provide the docker image to facilitate running the tool in the container.

Environmental requirements are as follows:

- docker

First, pull the container.

```bash
root@instance:/# docker pull <anonymous_or_placeholder>/ri:v2
```

Second, start the container.

```bash
root@instance:/# docker run -it <anonymous_or_placeholder>/ri:v2 bash
```

Then, in the container, run the tool. (Please note that it is **start.sh** that is executed here, not **start2.sh**.)

```bash
root@1a9c5cdda77b:/main# chmod +x start.sh
root@1a9c5cdda77b:/main# ./start.sh
```

## Result

After the tool runs, it will generate two files, *registry.txt* and *vendor.txt*, and the summary of these two files will be the final result.

Here are some examples of results.

```
volumeattributesclasses
validatingwebhookconfigurations
serviceaccounts
- /token
nodes
- /proxy
- /status
ingresses
- /status
deviceclasses
```

We also provide our detailed analysis results(i.e.,*registry.txt*, *vendor.txt* and *result.txt*(summary of the former two files)) in folder *ImplicitPermission/Resource_Identification_Analysis/results* for reference.

# Explicit Permission Analysis

Based on the the link between the method of resource storage object and resource verb, this tool collects all explicit permissions in kubernetes through static analysis. More specifically:

- For primary resources, our key observation is that all primary resources are linked to specific verbs through the methods of their storage objects. These methods define the operations that can be performed on the primary resource, providing a clear path to permission identification.

- For sub-resources, our observation is twofold. First, for some sub-resources, explicit permissions can still be identified using the same approach as primary resources. However, for other sub-resources, the explicit permissions are indicated through the array of HTTP methods returned by a unified `ConnectMethods`, which indirectly links these methods to specific API verbs.

## Usage

### Local Environment

This section explains the steps to run the tool by compiling the source code. 

Environmental requirements are as follows:

- Linux
- go1.23.0

First, download the kubernetes source code to the local machine. 

``````bash
root@instance:/# git clone https://github.com/kubernetes/kubernetes.git /kubernetes
root@instance:/# cd /kubernetes
root@instance:/kubernetes# git checkout v1.30.10
``````

Second, Install dependencies for the tool. We need to go to the folder corresponding to the tool. The folder is named *Explicit_Permission_Analysis*.

``````bash
root@instance:/# cd /ImplicitPermission/Explicit_Permission_Analysis/main
root@instance:/ImplicitPermission/Explicit_Permission_Analysis/main# go mod init ea
root@instance:/ImplicitPermission/Explicit_Permission_Analysis/main# go mod tidy
``````

Then, run the tool.

```bash
root@instance:/ImplicitPermission/Explicit_Permission_Analysis/main# chmod +x start.sh
root@instance:/ImplicitPermission/Explicit_Permission_Analysis/main# ./start.sh #
```

Or, We also provide a compiled binary file, which can be used for direct operation.

```bash
root@instance:/ImplicitPermission/Explicit_Permission_Analysis/main# chmod +x start2.sh
root@instance:/ImplicitPermission/Explicit_Permission_Analysis/main# ./start2.sh
```

### Docker Environment

We also provide the docker image to facilitate running the tool in the container.

Environmental requirements are as follows:

- docker

First, pull the container.

```bash
root@instance:/# docker pull <anonymous_or_placeholder>/ea:v2
```

Second, start the container.

```bash
root@instance:/# docker run -it <anonymous_or_placeholder>/ea:v2 bash
```

Then, in the container, run the tool. (Please note that it is **start.sh** that is executed here, not **start2.sh**.)

```bash
root@1a9c5cdda77b:/main# chmod +x start.sh
root@1a9c5cdda77b:/main# ./start.sh
```

## Result

After the tool runs, it will generate two files, *registry.txt* and *vendor.txt*, and the summary of these two files will be the final result.

Here are some examples of results.

```
volumeattributesclasses [Create Delete DeleteCollection Get List Update Watch Patch]
validatingwebhookconfigurations [Create Delete DeleteCollection Get List Update Watch Patch]
serviceaccounts [Create Delete DeleteCollection Get List Update Watch Patch]
serviceaccounts/token [Create]
nodes [Create Delete DeleteCollection Get List Update Watch Patch]
nodes/proxy [Get Create Update Patch Delete]
nodes/status [Get Update Patch]
ingresses [Create Delete DeleteCollection Get List Update Watch Patch]
ingresses/status [Get Update Patch]
resourceclaims [Create Delete DeleteCollection Get List Update Watch Patch]
```

We also provide our detailed analysis results(i.e.,*registry.txt*, *vendor.txt* and *result.txt*) in folder *ImplicitPermission/Explicit_Permission_Analysis/results* for reference.

# Combined LLM&Static permission analysis

We use a combined approach consists of LLM-based reasoning model and trace-based static analysis.

## LLM-based-analysis

Based on LLM, this paper analyzes the implicit permission references of primary resources and sub-resources in kubernetes.

For primary resources, after training the LLM through few-shot learning, we first conduct a resource reference analysis. Then, after providing explicit permissions, we perform an implicit permission analysis to obtain the implicit permission reference for the corresponding resources. And do self-reflection after each analysis. An example is as follows：

```
Prompt: As a Kubernetes expert, specializing in identifying API Resource Reference Analysis and API Resource Permission Reference Analysis. Your task is to make the following two analyses of kubernetes api resources provided by users: 1. API Resource Reference Analysis: Analyze dependencies, interactions, and relationships among Kubernetes API resources. 2.API Resource Permission Reference Analysis: Analyze the influence relationship between permissions, that is, one permission may trigger another permission.
Regarding the API resource reference analysis, it is defined as follows: In the context of Kubernetes, API resource reference analysis can be understood as analyzing the dependencies and interactions among API resources within Kubernetes. API Resource reference can be divided into resource reference and resource reference. Below are some examples:
1. For the Node resource, its Spec.Taints field is related to the scheduling of Pod resources. The values of the Taint field affect the creation and deletion of Pod resources. Therefore, this is an example of resource reference: Node --> Pod.
2. For the Daemonset resource, its Spec.Template field determines the state of the Pods it manages. Therefore, it can be considered a resource reference: Daemonset --> Pod.
3. For the StatefulSet resource, its Spec.Template field determines the state of the Pod resources it manages. Modifying the content of this field will also cause corresponding changes in the associated Pods. Therefore, this is an example of resource reference: StatefulSet --> Pod.
4. For the Job resource, its Spec.Template field determines the state of the Pods it manages. Therefore, this is an example of resource reference: Job --> Pod.
5. For the ClusterRoleBinding resource, it can associate a ServiceAccount with a ClusterRole, thus creating a reference from ClusterRoleBinding to ClusterRole.
Regarding the API resource permission reference analysis, it is defined as follows: Based on API resource reference analysis, the analysis incorporates the resource's verb to further examine the feasibility of the reference as well as the specific content and functionality of the reference. Below are some examples:
1. For example 1 in the above resource reference, the permission reference analysis is as follows: Modifying the taint field of a Node resource can trigger the deletion of some specific Pods. From this, we can derive the permission reference: patch Node --> delete Pod, update Node --> delete Pod, etc.
2. For example 2 in the above resource reference, the permission reference analysis is as follows: Deleting Daemonset can lead to the deletion of corresponding Pod resources. From this, we can derive the permission reference: delete Daemonset --> delete Pod, deletecollection Daemonset --> delete Pod, etc.
3. For example 3 in the above resource reference, the permission reference analysis is as follows: Modifying the spec.template of StatefulSet resources can result in Modifying corresponding Pod resources, and modifying the spec.replicas of StatefulSet can result in creation and deletion the corresponding pod. From this, we can derive the permission reference: patch StatefulSet --> patch Pod, patch StatefulSet --> create Pod, patch StatefulSet --> delete Pod, update StatefulSet --> update Pod, etc.
4. For example 4 in the above resource reference, the permission reference analysis is as follows: Creating a Job resource can control the creation of Pod resources. From this, we can derive the permission reference: create Job --> create Pod, etc.
5. For example 5 in the above resource reference, the permission reference analysis is as follows: Creating a ClusterRoleBinding can bind a ClusterRole to a ServiceAccount. The cluster by default has the cluster-admin ClusterRole, which possesses all permissions. Therefore, the following permission reference can be derived: create ClusterRoleBinding --> * *.
Do you understand the above two concepts, and are you ready to start the analysis? Answer yes or no.

Answer: 
Yes, I understand the above two concepts and am ready to start the analysis.
The API resource reference analysis for Service resources is as follows:
Service --> EndpointSlice
Service --> Endpoints
Service --> Pod

Prompt: Review your answer against the initial definitions:  
1. Did you avoid introducing unrelated resources?
Answer "Pass" if compliant, or "Fail: [reason]" if not.
If the answer is fail, please correct the result.

Answer: 
Pass

Prompt: The verbs supported by services resource include: [Create Delete DeleteCollection Get List Update Watch Patch] 
please make the API resource permission reference analysis based on the results of the API resource reference analysis. Just list the final results of permission reference, such as 'verb1 services --> verb2 otherRes', without explanation.

Answer: 
Here is the API resource permission reference analysis based on the provided verbs and previous resource reference results:
create services --> create EndpointSlice
create services --> create Endpoints
update services --> update EndpointSlice
update services --> update Endpoints
patch services --> patch EndpointSlice
patch services --> patch Endpoints
delete services --> delete EndpointSlice
delete services --> delete Endpoints
deletecollection services --> delete EndpointSlice
deletecollection services --> delete Endpoints

Prompt: Review your answer against the initial definitions:
1. Did you avoid introducing unrelated permission references?
Answer "Pass" if compliant, or "Fail: [reason]" if not.
If the answer is fail, please correct the result.

Answer: 
Pass
```

The final analysis results are in the *ImplicitPermission/Combined_LLM&Static_permission_analysis/Implicit_Permission_Analysis/primary/permission-reference.txt* file, and the all question-and-answer content is in the *ImplicitPermission/Combined_LLM&Static_permission_analysis/Implicit_Permission_Analysis/primary/results* folder.

For sub-resources, after providing the concept of basic sub-resource resource reference and permission reference for the LLM, we first conduct a resource reference analysis. Then, after providing explicit permissions, we perform an implicit permission analysis to obtain the implicit permission reference for the corresponding resources. And do self-reflection after each analysis. An example is as follows：

```
Prompt: As a Kubernetes expert, specializing in identifying API Sub-Resource reference and API Sub-Resource Permission Reference. Your task is to make the sub-resource reference analysis and sub-resource permission reference analysis.
Regarding the API Sub-Resource Reference analysis, it is defined as follows: In the context of Kubernetes, sub-resource reference analysis can be understood as analyzing the relationship between sub-resources and other resources. Below are some examples:
1. For pods/exec, creating pods/exec can execute commands in Pod, and secrets is mounted in pod, so there are the following resource reference: pods/exec --> secrets.
2. For pods/eviction, creating pods/eviction can expel the specified pod, so there are the following resource reference: pods/eviction --> pods.
3. For replicasets/scale, updating replicasets/scale can update the number of pods, so there are the following resource reference: replicasets/scale --> pods.
4. For nodes/status, updating nodes/status can update the status field of node, so there are the following resource reference: nodes/status --> nodes.
5. For statefulsets/scale, updating statefulsets/scale can update the number of pods, so there are the following resource reference: statefulsets/scale --> pods.
Regarding the API Sub-Resource Permission Reference analysis, it is defined as follows: In the context of Kubernetes, sub-resource permission reference analysis can be understood as analyzing how operations on sub-resources might affect other API resources or trigger operations on other API resources. Below are some examples:
1. For pod/exec, creating pods/exec can access the terminal session of a pod and access the contents of secrets mounted in the pod. Therefore, it can be concluded: create pods/exec --> get secrets.
2. For pods/eviction, creating pods/eviction can delete the specified pod. Therefore, it can be concluded: create pods/eviction --> delete pod.
3. For replicasets/scale, patching or updating replicasets/scale can adjust the number of Pods managed by the ReplicaSets, thereby increasing or decreasing the number of Pod resources. Therefore, it can be concluded: patch replicasets/scale --> create Pod, update replicasets/scale --> create Pod, patch replicasets/scale --> delete Pod, update replicasets/scale --> delete Pod.
4. For nodes/status, patching or updating nodes/status can affect the status of Nodes. Therefore, it can be concluded: patch nodes/status --> patch nodes, update nodes/status --> update nodes.
5. For statefulsets/scale, patching or updating statefulsets/scale can adjust the number of Pods managed by the StatefulSets, thereby increasing or decreasing the number of Pod resources. Therefore, it can be concluded: patch statefulsets/scale --> create Pod, update statefulsets/scale --> create Pod, patch statefulsets/scale --> delete Pod, update statefulsets/scale --> delete Pod.
Do you understand the above concepts, and are you ready to start the analysis? Answer yes or no.

Answer: 
Yes.

Prompt: Please make the API Sub-Resource Reference analysis of deployments/scale. Just list the final results such as 'deployments/scale --> otherRes', without explanation.

Answer: 
deployments/scale --> pods

Prompt: Review your answer against the initial definitions:  
1. Did you avoid introducing unrelated resources?
Answer "Pass" if compliant, or "Fail: [reason]" if not.
If the answer is fail, please correct the result.

Answer: 
Pass

Prompt: The verbs supported by deployments/scale resource include: [Get Update Patch]
Based on the verb obtained above, please make the subresource permission reference analysis of deployments/scale. Just list the results of permission reference, such as 'verb deployments/scale --> create B', without explanation.

Answer:
update deployments/scale --> create pods
update deployments/scale --> delete pods
patch deployments/scale --> create pods
patch deployments/scale --> delete pods

Prompt: Review your answer against the initial definitions:
1. Did you avoid introducing unrelated permission references?  
Answer "Pass" if compliant, or "Fail: [reason]" if not.
If the answer is fail, please correct the result.

Answer: 
Pass
```



The final analysis results are in the *ImplicitPermission/Combined_LLM&Static_permission_analysis/Implicit_Permission_Analysis/sub/permission-reference.txt* file, and the specific question-and-answer content is in the *ImplicitPermission/Combined_LLM&Static_permission_analysis/Implicit_Permission_Analysis/sub/results* folder.

**Due to the dynamic nature of large language models (LLMs), the results may vary slightly across different interactions. Therefore, all the results provided here should be considered as reference.**

## Static Analysis

Implicit permissions are essentially the semantic equivalence of operations resulting from explicit permissions. Therefore, by tracking the controller control loops, the impacts of these permissions can be traced.

Based on the static analysis of each controller control loop in kubernetes, this tool realizes the analysis of implicit permissions in kubernetes. It is used for comparison with LLM analysis scheme.

## Usage

### Local Environment

This section explains the steps to run the tool by compiling the source code. 

Environmental requirements are as follows:

- Linux
- go1.23.0

First, download the kubernetes source code to the local machine. 

``````bash
root@instance:/# git clone https://github.com/kubernetes/kubernetes.git /kubernetes
root@instance:/# cd /kubernetes
root@instance:/kubernetes# git checkout v1.30.10
``````

Second, Install dependencies for the tool. We need to go to the folder corresponding to the tool. The folder is named *Static Analysis*.

``````bash
root@instance:/# cd /ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/SA
root@instance:/ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/SA# go mod init sa
root@instance:/ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/SA# go mod tidy
``````

Then, run the tool.

```bash
root@instance:/ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/SA# go run .
```

Or, We also provide a compiled binary file, which can be used for direct operation.

```bash
root@instance:/ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/SA# chmod +x ./sa
root@instance:/ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/SA# ./sa
```

### Docker

We also provide the docker image to facilitate running the tool in the container.

Environmental requirements are as follows:

- docker

First, pull the container.

```bash
root@instance:/# docker pull <anonymous_or_placeholder>/sa:v4
```

Second, start the container.

```bash
root@instance:/# docker run -it <anonymous_or_placeholder>/sa:v4 bash
```

Then, in the container, run the tool.

```bash
root@1a9c5cdda77b:/SA# go run .
```

## Result

After the tool runs, a file *result.txt* will be generated, and the content of this file is the result.

The results are shown as:

```
delete serviceAccounts --> delete secrets
delete job --> patch controllerRevisions
delete job --> patch replicaSets
delete job --> create pods
delete job --> delete pods
delete job --> patch pods
delete PersistentVolume --> update persistentVolumes
update prioritylevelconfigurations/status --> update prioritylevelconfigurations
update persistentvolumeclaims/status --> update persistentvolumeclaims
delete statefulSets --> create controllerRevisions
...
```

We also provide our detailed analysis results(i.e.,*result.txt*) in folder */ImplicitPermission/Combined_LLM&Static_permission_analysis/Static_Analysis/results* for reference.

# Dynamic validation

There are several challenges when conducting dynamic trigger testing: 1. Implicit permissions are the semantic equivalents of operations resulting from explicit permissions. Therefore, when triggered, relevant domain knowledge is required to understand the outcomes of the trigger; 2. The triggers depend on the experience and understanding of Kubernetes experts. Therefore, based on our domain knowledge and experience, we conducted trigger testing on the results and provide a validated list of 328 triggerable reference results here (this result is located in the *ImplicitPermission/Combined_LLM&Static_permission_analysis/assessment/trigger.txt* file), along with a specific triggering example that can be referenced for trigger testing.

An example is as follows：

For the following reference:

```
create Replicaset --> create Pod
```

The test process is as follows:

[1]Use `kubectl` to enumerate the pods that exist in the default namespace of the cluster.

```bash
root@instance:/# kubectl get pods
```

By default, there are no pods in the default namespace, so the result returns: "No resources found in default namespace."

[2]Execute the following command to create a ReplicaSet resource in Kubernetes.

```bash
root@instance:/# cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: my-replicaset
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-container
        image: nginx
        ports:
        - containerPort: 80
EOF
```

[3]Use `kubectl` to check again for the pods that exist in the default namespace.

```bash
root@instance:/# kubectl get pods
```

It can be observed that there are 3 additional pods, and the result is similar to the following.

```
NAME                  READY   STATUS              RESTARTS   AGE
my-replicaset-58h75   0/1     ContainerCreating   0          1s
my-replicaset-ghdn9   0/1     ContainerCreating   0          1s
my-replicaset-k7s7m   0/1     ContainerCreating   0          1s
```

This result indicates that creating a ReplicaSet triggers the creation of pods.

# FNR Assessment

We manually constructed a set containing 50 permission references based on our domain knowledge of Kubernetes (the set is located in the *ImplicitPermission/Combined_LLM&Static_permission_analysis/assessment/base.txt* file).

We compared it with the trigger references identified by the Combined LLM&Static permission analysis and found that the Combined LLM&Static permission analysis results included 47 out of the 50 references, missing 3. Therefore, the false negative rate is 6%.

The detailed data are as follows(references wrapped in ** are missing references.):

```
**`create secrets` --> `create serviceaccounts/token`**
**`get secrets` => `get serviceaccounts/token`**
**`create Pod` --> `create serviceaccounts/token`**
`update namespaces/finalize` --> `update namespace`
`create RoleBinding` --> `bind Role`
`create CronJob` --> `create Job`
`create DaemonSet` --> `create Pod`
`create Deployment` --> `create Pod`
`create HorizontalPodAutoscaler` --> `update Scale`
`create Job` --> `create Pod`
`create Pod` --> `get ConfigMap`
`create Pod` --> `get Secret`
`create ReplicaSet` --> `create Pod`
`create ReplicationController` --> `create Pod`
`create StatefulSet` --> `create Pod`
`deletecollection CronJob` --> `delete Job`
`deletecollection CustomResourceDefinition` --> `delete CR`
`deletecollection DaemonSet` --> `delete Pod`
`deletecollection Deployment` --> `delete Pod`
`deletecollection Job` --> `delete Pod`
`deletecollection ReplicationController` --> `delete Pod`
`deletecollection ServiceAccount` --> `delete Secret`
`deletecollection StatefulSet` --> `delete Pod`
`delete CronJob` --> `delete Job`
`delete CustomResourceDefinition` --> `delete CR`
`delete DaemonSet` --> `delete Pod`
`delete Deployment` --> `delete Pod`
`delete Job` --> `delete Pod`
`delete ReplicationController` --> `delete Pod`
`delete ServiceAccount` --> `delete Secret`
`delete StatefulSet` --> `delete Pod`
`update CronJob` --> `create Job`
`update CronJob` --> `delete Job`
`update DaemonSet` --> `create Pod`
`update DaemonSet` --> `delete Pod`
`update DaemonSet` --> `update Pod`
`update Deployment` --> `create Pod`
`update Deployment` --> `delete Pod`
`update Deployment` --> `update Pod`
`update nodes` --> `delete Pod`
`update ReplicaSet` --> `create Pod`
`update ReplicaSet` --> `delete Pod`
`update namespaces/finalize` --> `delete namespaces`
`patch Deployment` --> `create Pod`
`patch Deployment` --> `delete Pod`
`patch StatefulSet` --> `create Pod`
`patch StatefulSet` --> `delete Pod`
`patch ReplicaSet` --> `create Pod`
`patch ReplicaSet` --> `delete Pod`
`patch nodes` --> `delete Pod`
```

# Other LLM

We also carried out experiments with other LLM, and the results were placed in */ImplicitPermission/Combined_LLM&Static_permission_analysis/other_LLM*

