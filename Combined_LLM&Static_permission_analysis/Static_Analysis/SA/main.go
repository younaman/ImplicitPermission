package main

import (
	"fmt"
	"go/ast"
	"os"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
)

var (
	rootDir       = "/kubernetes/"
	funcFileName  = "./methods.tmp"
	pkgPath       = rootDir
	inputFile     = "input"
	resultFile    = "result"
	FilteredGraph *callgraph.Graph
	Pkgs          []*packages.Package

	RegistryPkgs    []*packages.Package
	StartFuncs      map[string][]string
	registryPkgPath = rootDir + "pkg/registry"
)

func main() {
	Before()
	file, err := os.OpenFile(inputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	originalStdout := os.Stdout
	//defer file.Close()
	os.Stdout = file

	Build(pkgPath)
	structs := FindStructsAndNewFuncs(Pkgs)

	for _, structInfo := range structs {
		if structInfo.RunMethod != nil {
			flag := 0
			if structInfo.StructNode != nil && structInfo.StructNode.Fields != nil {
				for _, field := range structInfo.StructNode.Fields.List {
					if s, ok := field.Type.(*ast.SelectorExpr); ok {
						if i, ok := s.X.(*ast.Ident); ok {
							if strings.Contains(i.Name, "workqueue") {
								flag += 1
							}
						}
					} else if len(field.Names) > 0 && strings.Contains(strings.ToLower(field.Names[0].Name), "queue") {
						flag += 1
					}
					// if (strings.Contains(field.Type.(*ast.SelectorExpr).X.(*ast.Ident).Name, "workqueue")) || strings.Contains(strings.ToLower(field.Names[0].Name), "queue") {
					// 	flag += 1
					// }
				}
			}
			startType := 0
			startVRes := map[string][]string{}
			startFuncs := map[string]string{}
			// if flag >= 2 {
			// 	fmt.Println("queue Controller:", structInfo.RunMethod.FullName())
			// 	fmt.Println("==========================================")
			// 	continue
			// }

			for _, new := range structInfo.NewFuncs {
				for _, call := range new.CallDetails {
					if startVRes[call.Caller] == nil {
						// if call.Caller == "" {
						// 	fmt.Println("inform:", structInfo.RunMethod.FullName())
						// }
						startVRes[call.Caller] = make([]string, 0)
					}
					for _, verb := range call.HandlerFuncs {
						startVRes[call.Caller] = append(startVRes[call.Caller], "."+verb)
						//startVRes[call.Caller] = append(startVRes[call.Caller], call.Caller+"."+verb)
						//startVRes = append(startVRes, call.Caller+"."+verb)
					}
					// fmt.Printf("Resource: %s\n", call.Caller)
					// fmt.Printf("Verbs: %v\n", call.HandlerFuncs)
				}
			}

			switch structInfo.RunMethod.FullName() {
			case "(*k8s.io/kubernetes/pkg/controller/replicaset.ReplicaSetController).Run":
				delete(startVRes, "podInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/certificates/rootcacertpublisher.Publisher).Run":
				delete(startVRes, "cmInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/deployment.DeploymentController).Run":
				delete(startVRes, "podInformer.Informer()")
				delete(startVRes, "rsInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/volume/ephemeral.ephemeralController).Run":
				delete(startVRes, "pvcInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/resourceclaim.Controller).Run":
				startType = 1
				startFuncs["podInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/resourceclaim.Controller).syncPod"
				startFuncs["resourceClaimInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/resourceclaim.Controller).syncClaim"
			case "(*k8s.io/kubernetes/pkg/controller/serviceaccount.TokensController).Run":
				startType = 1
				startFuncs["serviceAccounts.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/serviceaccount.TokensController).syncServiceAccount"
				startFuncs["secrets.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/serviceaccount.TokensController).syncSecret"
			case "(*k8s.io/kubernetes/pkg/controller/storageversiongc.Controller).Run":
				startType = 1
				startFuncs["leaseInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/storageversiongc.Controller).runLeaseWorker"
				startFuncs["storageVersionInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/storageversiongc.Controller).runStorageVersionWorker"
			case "(*k8s.io/kubernetes/pkg/controller/cronjob.ControllerV2).Run":
				delete(startVRes, "jobInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/garbagecollector.GraphBuilder).Run":
				continue
			case "(*k8s.io/kubernetes/pkg/controller/job.Controller).Run":
				startVRes["jobInformer.Informer()"] = append(startVRes["jobInformer.Informer()"], ".AddFunc", ".UpdateFunc", ".DeleteFunc")
			case "(*k8s.io/kubernetes/pkg/controller/daemon.DaemonSetsController).Run":
				delete(startVRes, "historyInformer.Informer()")
				delete(startVRes, "podInformer.Informer()")
				delete(startVRes, "nodeInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/servicecidrs.Controller).Run":
				delete(startVRes, "ipAddressInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/serviceaccount.ServiceAccountsController).Run":
				delete(startVRes, "saInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/statefulset.StatefulSetController).Run":
				delete(startVRes, "podInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/endpoint.Controller).Run":
				delete(startVRes, "podInformer.Informer()")
				delete(startVRes, "endpointsInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/volume/attachdetach.attachDetachController).Run":
				delete(startVRes, "podInformer.Informer()")
				delete(startVRes, "nodeInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/volume/pvcprotection.Controller).Run":
				delete(startVRes, "podInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/podgc.PodGCController).Run":
				continue
			case "(*k8s.io/kubernetes/pkg/controller/garbagecollector.GarbageCollector).Run":
				continue
			case "(*k8s.io/kubernetes/pkg/controller/tainteviction.Controller).Run":
				startType = 1
				startFuncs["podInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/tainteviction.Controller).handlePodUpdate"
				startFuncs["nodeInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/tainteviction.Controller).handleNodeUpdate"
			case "(*k8s.io/kubernetes/pkg/controller/disruption.DisruptionController).Run":
				continue
			case "(*k8s.io/kubernetes/pkg/controller/nodelifecycle.Controller).Run":
				continue
			case "(*k8s.io/kubernetes/pkg/controller/bootstrap.Signer).Run":
				delete(startVRes, "secrets.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/endpointslice.Controller).Run":
				delete(startVRes, "podInformer.Informer()")
				delete(startVRes, "endpointSliceInformer.Informer()")
				delete(startVRes, "nodeInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/endpointslicemirroring.Controller).Run":
				delete(startVRes, "endpointSliceInformer.Informer()")
				delete(startVRes, "endpointsInformer.Informer()")
			case "(*k8s.io/kubernetes/pkg/controller/resourcequota.Controller).Run":
				startVRes["ResourceQuotaInformer.Informer()"] = startVRes[""]
				delete(startVRes, "")
				//fmt.Println("test1:", startVRes)
			case "(*k8s.io/kubernetes/pkg/controller/volume/persistentvolume.PersistentVolumeController).Run":
				startType = 1
				startFuncs["PersistentVolumeInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/volume/persistentvolume.PersistentVolumeController).volumeWorker"
				startFuncs["PersistentVolumeClaimInformer.Informer()"] = "(*k8s.io/kubernetes/pkg/controller/volume/persistentvolume.PersistentVolumeController).claimWorker"
				startVRes["PersistentVolumeInformer.Informer()"] = startVRes[""]
				startVRes["PersistentVolumeClaimInformer.Informer()"] = startVRes[""]
				delete(startVRes, "")
				//fmt.Println("test2:", startFuncs, startVRes)
			default:
				//fmt.Println("queue, inform", structInfo.RunMethod.FullName())
			}

			if len(startVRes) == 0 {
				continue
			}
			if startType == 1 {
				start2(startVRes, startFuncs)
				continue
			}
			startFunc := structInfo.RunMethod.FullName()
			//startFunc := strings.TrimPrefix(structInfo.RunMethod.FullName(), "func ")
			//startFunc = strings.TrimSuffix(startFunc, "()")
			start(startVRes, startFunc)
			//fmt.Println("==========================================")
		}
	}
	// for _, startFunc := range startFuncs {
	// 	flag := false

	// 	if !flag {
	// 		fmt.Println("[X] no call found:", startFunc)
	// 	}
	// 	fmt.Println("=================================================================")

	// }
	os.Stdout = originalStdout
	file.Close()
	Extract(inputFile, resultFile)
	file, err = os.OpenFile(resultFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	os.Stdout = file
	Build0(registryPkgPath)
	a()
	refMap := map[string][][]string{}
	for subRes, startFuncs := range StartFuncs {
		//fmt.Println(subRes)
		refMap[subRes] = make([][]string, 0)
		for _, startFunc := range startFuncs {
			verb1 := strings.ToLower(startFunc[strings.LastIndex(startFunc, ".")+1:])
			result := findCall(startFunc)
			for verb2, _ := range result {
				r := []string{verb1, subRes, verb2, subRes[:strings.Index(subRes, "/")]}
				refMap[subRes] = append(refMap[subRes], r)
				//fmt.Println(verb1, subRes, "-->", verb2, subRes[:strings.Index(subRes, "/")])
			}
		}
		//fmt.Println("==========================================")
	}
	resultMap := map[string]string{}
	for _, refs := range refMap {
		flag := 0
		for _, ref := range refs {
			if ref[0] == "get" || ref[0] == "update" {
				flag++
			}
			resultMap[ref[0]+" "+ref[1]+" "+"-->"+" "+ref[2]+" "+ref[3]] = ""
			//fmt.Println(ref[0], ref[1], "-->", ref[2], ref[3])
			if flag == 2 {
				//fmt.Println("patch", ref[1], "-->", ref[2], ref[3])
			}
		}
	}
	for r, _ := range resultMap {
		fmt.Println(r)
	}
	os.Stdout = originalStdout
	file.Close()
	if err := removeDuplicateLines(resultFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	multiRef(resultFile, resultFile+".txt")
	DeleteTmpFiles([]string{"input", "tmp", "methods.tmp", resultFile})
}

func start(startVRes map[string][]string, startFunc string) {
	flag := false
	targetFuncs := ReadFiles(funcFileName)
	for _, targetFunc := range targetFuncs {
		//fmt.Println("start:", startFunc)
		if startFunc == "" {
			//fmt.Println("startFunc1 empty", startVRes)
			return
		}
		paths, found := FindAllPaths(startFunc, targetFunc)
		if !found {
			break
		}
		if len(paths) > 0 {
			flag = true
			for k, i := range startVRes {
				for _, j := range i {
					fmt.Printf("%s --> %s\n", k+j, targetFunc)
				}

			}

			// fmt.Println("All Call Paths:")
			// for i, path := range paths {
			// 	fmt.Printf("Path %d:\n", i+1)
			// 	for _, step := range path {
			// 		fmt.Println("  ", step)
			// 	}
			// }
		} else {
			//fmt.Printf("[X] Function %s does not indirectly call %s\n", startFunc, targetFunc)
		}
	}
	if !flag {
		//fmt.Println("no call found:", startFunc)
	}
}
func start2(startVRes map[string][]string, startFuncs map[string]string) {
	targetFuncs := ReadFiles(funcFileName)
	for startRes, i := range startVRes {
		flag := false
		for _, targetFunc := range targetFuncs {
			if startFuncs[startRes] == "" {
				//fmt.Println("startFunc2 empty", startVRes)
				return
			}
			//fmt.Println("start2:", startFuncs[startRes])
			paths, found := FindAllPaths(startFuncs[startRes], targetFunc)
			if !found {
				break
			}
			if len(paths) > 0 {
				flag = true
				for _, j := range i {
					fmt.Printf("%s --> %s\n", startRes+j, targetFunc)
				}

			}
		}
		if !flag {
			//fmt.Println("start2 no call found:", startFuncs[startRes])
		}
	}

}

