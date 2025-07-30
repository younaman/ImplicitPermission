package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"
)

type StructInfo struct {
	StructName string
	FilePath   string
	StructNode *ast.StructType
	RunMethod  *types.Func
	NewFuncs   []NewFuncInfo
}

type NewFuncInfo struct {
	FuncName    string
	FuncObj     *types.Func
	CallDetails []CallInfo
}

type CallInfo struct {
	Caller       string
	HandlerFuncs []string
}

type InterfaceInfo struct {
	Name    string
	Methods []MethodInfo
	File    string
}

type MethodInfo struct {
	Name       string
	Params     []Param
	Results    []Param
	IsVariadic bool
}

type Param struct {
	Name string
	Type string
}

type StructInfo2 struct {
	Name       string
	File       string
	EmbedGen   bool
	EmbedTypes []string
}

var (
	projectPath = rootDir + "pkg/controller"
)

func FindStructsAndNewFuncs(pkgs []*packages.Package) map[string]StructInfo {
	result := make(map[string]StructInfo)

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			structs := make(map[string]*ast.StructType)
			targetFile := false
			filePath := pkg.Fset.File(file.Pos()).Name() // Get the file path
			// if !strings.Contains(filePath, "pv_controller_base") {
			// 	continue
			// }
			// First pass: Find struct definitions and their "Run" methods
			ast.Inspect(file, func(n ast.Node) bool {
				// Find struct definitions
				if genDecl, ok := n.(*ast.GenDecl); ok {
					for _, spec := range genDecl.Specs {
						if typeSpec, ok := spec.(*ast.TypeSpec); ok {
							if structType, ok := typeSpec.Type.(*ast.StructType); ok {
								structs[typeSpec.Name.Name] = structType
							}
						}
					}
				}

				if funcDecl, ok := n.(*ast.FuncDecl); ok && funcDecl.Recv != nil {
					// Get receiver type
					for _, field := range funcDecl.Recv.List {
						var structName string
						// Handle pointer and value receivers
						if starExpr, ok := field.Type.(*ast.StarExpr); ok {
							if ident, ok := starExpr.X.(*ast.Ident); ok {
								structName = ident.Name
							}
						} else if ident, ok := field.Type.(*ast.Ident); ok {
							structName = ident.Name
						}

						if structName != "" && funcDecl.Name.Name == "Run" {
							uniqueKey := fmt.Sprintf("%s/%s", filePath, structName)
							if _, exists := result[uniqueKey]; !exists {
								result[uniqueKey] = StructInfo{
									StructName: structName,
									FilePath:   filePath,
									StructNode: structs[structName],
									RunMethod:  nil,
									NewFuncs:   []NewFuncInfo{},
								}
							}
							if obj, ok := pkg.TypesInfo.Defs[funcDecl.Name].(*types.Func); ok {
								info := result[uniqueKey]
								info.RunMethod = obj
								result[uniqueKey] = info
								targetFile = true
							}
						}
					}
				}
				return true
			})

			if targetFile {
				ast.Inspect(file, func(n ast.Node) bool {
					if funcDecl, ok := n.(*ast.FuncDecl); ok && funcDecl.Recv == nil {
						if strings.HasPrefix(funcDecl.Name.Name, "New") {
							callDetails := AnalyzeNewFunc(pkg, funcDecl.Body)

							for uniqueKey, info := range result {
								if info.FilePath == filePath {
									if obj, ok := pkg.TypesInfo.Defs[funcDecl.Name].(*types.Func); ok {
										info.NewFuncs = append(info.NewFuncs, NewFuncInfo{
											FuncName:    funcDecl.Name.Name,
											FuncObj:     obj,
											CallDetails: callDetails,
										})
										result[uniqueKey] = info
									}
								}
							}
						}
					}
					return true
				})
			}
		}
	}

	return result
}

func AnalyzeNewFunc(pkg *packages.Package, body *ast.BlockStmt) []CallInfo {
	var calls []CallInfo

	ast.Inspect(body, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				funcName := selExpr.Sel.Name
				if funcName == "AddEventHandler" || funcName == "AddEventHandlerWithResyncPeriod" {
					var caller string
					if x, ok := selExpr.X.(*ast.CallExpr); ok {
						if fun, ok := x.Fun.(*ast.SelectorExpr); ok {
							if ident, ok := fun.X.(*ast.Ident); ok {
								caller = fmt.Sprintf("%s.%s()", ident.Name, fun.Sel.Name)
							}
						}
					}

					var handlerFuncs []string
					if len(callExpr.Args) > 0 {
						handlerFuncs = ExtractHandlerFuncs(callExpr.Args[0])
					}

					calls = append(calls, CallInfo{
						Caller:       caller,
						HandlerFuncs: handlerFuncs,
					})
				}
			}
		}
		return true
	})

	return calls
}

func ExtractHandlerFuncs(arg ast.Expr) []string {
	var handlerFuncs []string

	if compositeLit, ok := arg.(*ast.CompositeLit); ok {
		for _, elt := range compositeLit.Elts {
			if kvExpr, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kvExpr.Key.(*ast.Ident); ok && key.Name == "Handler" {
					handlerFuncs = append(handlerFuncs, ExtractHandlerFuncs(kvExpr.Value)...)
				} else if key, ok := kvExpr.Key.(*ast.Ident); ok {
					handlerFuncs = append(handlerFuncs, key.Name)
				}
			}
		}
	}

	return handlerFuncs
}

func FilterGraph(graph *callgraph.Graph) *callgraph.Graph {
	filteredGraph := callgraph.New(graph.Root.Func)
	nodeMap := map[*callgraph.Node]*callgraph.Node{}

	for _, node := range graph.Nodes {
		if node.Func != nil && node.Func.Pkg != nil && strings.HasPrefix(node.Func.Pkg.Pkg.Path(), "k8s.io") {
			newNode := filteredGraph.CreateNode(node.Func)
			nodeMap[node] = newNode
		}
	}

	for _, node := range graph.Nodes {
		if _, ok := nodeMap[node]; !ok {
			continue
		}
		for _, edge := range node.Out {
			if _, ok := nodeMap[edge.Callee]; ok {
				callgraph.AddEdge(nodeMap[node], edge.Site, nodeMap[edge.Callee])
			}
		}
	}

	return filteredGraph
}

func Build(pkgPath string) {
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Tests: false, Dir: pkgPath}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		log.Fatalf("Failed to load packages: %v", err)
	}
	for _, i := range pkgs {
		if len(i.Errors) != 0 {
			fmt.Println("ERROR!!!", i.Errors)
		}
	}
	prog, _ := ssautil.AllPackages(pkgs, 0)
	prog.Build()

	graph := cha.CallGraph(prog)
	FilteredGraph = FilterGraph(graph)

	cfg = &packages.Config{
		Mode: packages.LoadSyntax,
		Dir:  projectPath,
	}
	Pkgs, _ = packages.Load(cfg, "./...")
}
func Build0(pkgPath string) {
	StartFuncs = make(map[string][]string)
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Tests: false, Dir: pkgPath}
	RegistryPkgs, _ = packages.Load(cfg, "./...")
	for _, i := range RegistryPkgs {
		if len(i.Errors) != 0 {
			fmt.Println("ERROR!!!", i.Errors)
		}
	}

}

func FindAllPaths(startFunc, targetFunc string) ([][]string, bool) {
	visited := make(map[*callgraph.Node]bool)
	var paths [][]string
	var currentPath []string

	var startNode *callgraph.Node
	for _, node := range FilteredGraph.Nodes {
		if node.Func != nil && node.Func.String() == startFunc { //strings.HasSuffix(node.Func.String(), startFunc)
			// for _, i := range node.Out {
			// 	fmt.Println(i)
			// }
			startNode = node
			break
		}
	}
	if startNode == nil {
		log.Printf("Function %s not found in the call graph", startFunc)
		return paths, false
	}

	var dfs func(node *callgraph.Node) bool
	dfs = func(node *callgraph.Node) bool {
		if visited[node] {
			return false
		}
		visited[node] = true
		if node.Func != nil && node.Func.Pkg != nil && (strings.HasPrefix(node.Func.Pkg.Pkg.Path(), "k8s.io/kubernetes/pkg/controller") || strings.HasPrefix(node.Func.Pkg.Pkg.Path(), "k8s.io/client-go")) {
			if strings.HasPrefix(node.Func.Pkg.Pkg.Path(), "k8s.io/client-go") && !strings.Contains(node.Func.String(), targetFunc) {
				return false
			}
			currentPath = append(currentPath, node.Func.String())
			defer func() { currentPath = currentPath[:len(currentPath)-1] }()

			//re := regexp.MustCompile(regexp.QuoteMeta(targetFunc) + `[^A-Za-z]*$`)
			if !strings.Contains(strings.ToLower(node.Func.String()), "fake") && node.Func.String() == targetFunc { //re.MatchString(node.Func.String())
				paths = append(paths, append([]string(nil), currentPath...))
				return true
			}

			for _, edge := range node.Out {
				dfs(edge.Callee)
			}
		}
		return false
	}

	dfs(startNode)
	return paths, true
}
func Extract(inputFile, outputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("fail to open %s: %v\n", inputFile, err)
		return
	}
	defer file.Close()

	re := regexp.MustCompile(`(?P<source>\w+)(Informer\.Informer\(\))?\.(?P<operation>\w+Func)? --> \(\*k8s\.io/client-go/kubernetes/typed/(?P<group>[\w/]+)\.(?P<resource>[\w]+)\)\.(?P<method>\w+)`)
	re2 := regexp.MustCompile(`(?P<source>\w+)(\.Informer\(\))?\.(?P<operation>\w+Func)? --> \(\*k8s\.io/client-go/kubernetes/typed/(?P<group>[\w/]+)\.(?P<resource>[\w]+)\)\.(?P<method>\w+)`)
	var simplifiedData []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		matches2 := re2.FindStringSubmatch(line)
		if matches == nil && matches2 == nil {
			fmt.Println(line)
			continue
		}
		if matches != nil {
			source := matches[1]
			operation := matches[3]
			resource := matches[5]
			method := strings.ToLower(matches[6])

			action := mapOperationToAction(operation)
			if action == "unknown" {
				continue
			}
			switch source {
			case "ns":
				source = "namespaces"
			case "d":
				source = "deployments"
			case "set":
				source = "statefulSets"
			case "rs":
				source = "replicaSets"
			case "pv":
				source = "PersistentVolume"
			case "pvc":
				source = "persistentVolumeClaim"
			}
			simplified := fmt.Sprintf("%s %s --> %s %s", action, source, method, resource)
			simplifiedData = append(simplifiedData, simplified)
		} else if matches2 != nil {
			source := matches2[1]
			operation := matches2[3]
			resource := matches2[5]
			method := strings.ToLower(matches2[6])

			action := mapOperationToAction(operation)
			if action == "unknown" {
				continue
			}
			switch source {
			case "ns":
				source = "namespaces"
			case "d":
				source = "deployments"
			case "set":
				source = "statefulSets"
			case "rs":
				source = "replicaSets"
			case "pv":
				source = "PersistentVolume"
			case "pvc":
				source = "persistentVolumeClaim"
			}
			simplified := fmt.Sprintf("%s %s --> %s %s", action, source, method, resource)
			simplifiedData = append(simplifiedData, simplified)
		}

	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("fail to read: %v\n", err)
		return
	}

	simplifiedData = removeDuplicates(simplifiedData)
	tmpFile := "tmp"
	err = writeToFile(tmpFile, simplifiedData)
	if err != nil {
		fmt.Printf("fail to write: %v\n", err)
		return
	}

	//fmt.Printf("%s\n", tmpFile)
	file, err = os.Open(tmpFile)
	if err != nil {
		fmt.Printf("can not open %s: %v\n", tmpFile, err)
		return
	}
	defer file.Close()

	var filteredData []string

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " --> ")
		if len(parts) != 2 {
			continue
		}

		resA := getResource(parts[0])
		resB := getResource(parts[1])
		verbA := getVerb(parts[0])
		verbB := getVerb(parts[1])

		if !eq(resA, resB) && verbB != "get" && verbB != "list" {
			filteredData = append(filteredData, line)
			rsc(resA, resB, verbA, verbB, &filteredData)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("fail to read: %v\n", err)
		return
	}

	err = writeToFile(outputFile, filteredData)
	if err != nil {
		fmt.Printf("fail to write: %v\n", err)
		return
	}

	//fmt.Printf("%s\n", outputFile)
}

func mapOperationToAction(operation string) string {
	switch operation {
	case "AddFunc":
		return "create"
	case "UpdateFunc":
		return "update"
	case "DeleteFunc":
		return "delete"
	default:
		return "unknown"
	}
}

func removeDuplicates(data []string) []string {
	uniqueMap := make(map[string]struct{})
	var result []string
	for _, item := range data {
		if _, exists := uniqueMap[item]; !exists {
			uniqueMap[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func writeToFile(filename string, data []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range data {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

func getResource(part string) string {
	parts := strings.Split(part, " ")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func getVerb(part string) string {
	parts := strings.Split(part, " ")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}
func eq(res1, res2 string) bool {
	if res1 == res2 || (res1+"s" == res2) || (res1 == res2+"s") {
		return true
	}
	return false
}

func readFiels(funcFileName string) []string {
	var targetFuncs []string
	funcFile, _ := os.Open(funcFileName)
	defer funcFile.Close()
	scanner := bufio.NewScanner(funcFile)
	for scanner.Scan() {
		line := scanner.Text()
		targetFuncs = append(targetFuncs, line)
	}
	return targetFuncs
}

func findRes(funcDecl *ast.FuncDecl, pkg *packages.Package) {
	for _, stmt := range funcDecl.Body.List {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok {
			resource := ""
			if initStmt, ok := ifStmt.Init.(*ast.AssignStmt); ok {
				if ident, ok := initStmt.Lhs[0].(*ast.Ident); ok {
					if ident.Name == "resource" {
						if value, ok := initStmt.Rhs[0].(*ast.BasicLit); ok {
							resource = strings.Trim(value.Value, "\"")
						}
					}

				}

			}
			if resource == "" {
				continue
			}
			ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
				if assignStmt, ok := n.(*ast.AssignStmt); ok {
					subResource := ""
					for _, lhs := range assignStmt.Lhs {
						if ident, ok := lhs.(*ast.IndexExpr); ok {
							if binaryExpr, ok := ident.Index.(*ast.BinaryExpr); ok && binaryExpr.Op == token.ADD {
								if basicLit, ok := binaryExpr.Y.(*ast.BasicLit); ok && basicLit.Kind == token.STRING {
									subResource = strings.Trim(basicLit.Value, "\"")
								}
							}
						}
					}
					for _, expr := range assignStmt.Rhs {
						typ := pkg.TypesInfo.Types[expr].Type
						if typ != nil {
							//fmt.Println(reflect.TypeOf(typ))
							if _, ok := typ.(*types.Pointer); ok {
								if subResource != "" {
									fullName := resource + subResource
									printMethods(fullName, typ)
								}
							}

						}

					}
				}
				return true
			})
		}

	}
}
func printMethods(fullName string, typ types.Type) {
	methodSet := types.NewMethodSet(typ)
	for i := 0; i < methodSet.Len(); i++ {
		sel := methodSet.At(i)
		fn, ok := sel.Obj().(*types.Func)
		if !ok {
			continue
		}

		sig, ok := fn.Type().(*types.Signature)
		if !ok {
			continue
		}
		recvType := sig.Recv().Type()

		fullType := types.TypeString(recvType, func(pkg *types.Package) string {
			return pkg.Path()
		})

		fullMethodName := fmt.Sprintf("(%s).%s", fullType, fn.Name())
		if check(fullMethodName) {
			if StartFuncs[fullName] == nil {
				StartFuncs[fullName] = make([]string, 0)
			}
			StartFuncs[fullName] = append(StartFuncs[fullName], fullMethodName)
		}

	}
}
func check(s string) bool {
	s = strings.ToLower(s)
	verbs := []string{"update", "delete", "deletecollection", "patch", "create"}
	for _, v := range verbs {
		if s[strings.LastIndex(s, ".")+1:] == v {
			return true
		}
	}
	return false
}
func a() {
	for _, pkg := range RegistryPkgs {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if funcDecl, ok := decl.(*ast.FuncDecl); ok {
					if funcDecl.Body != nil {
						findRes(funcDecl, pkg)
					}
				}
			}
		}
	}
}
func findCall(startFunc string) map[string]string {
	result := map[string]string{}
	for _, node := range FilteredGraph.Nodes {
		if node.Func != nil && node.Func.String() == startFunc {
			for _, i := range node.Out {
				if strings.Contains(i.String(), "(*k8s.io/apiserver/pkg/registry/generic/registry.Store).Update") {
					result["update"] = ""

				} else if strings.Contains(i.String(), "(*k8s.io/apiserver/pkg/registry/generic/registry.Store).Create") {
					result["create"] = ""

				} else if strings.Contains(i.String(), "(*k8s.io/apiserver/pkg/registry/generic/registry.Store).Delete") {
					result["delete"] = ""

				} else if strings.Contains(i.String(), "(*k8s.io/apiserver/pkg/registry/generic/registry.Store).DeleteCollection") {
					result["deletecollection"] = ""
					fmt.Println(startFunc, "=>", "store.DeleteCollection")
				}

			}
			break
		}
	}
	return result
}
func collect() {
	myrootDir := rootDir + "staging/src/k8s.io/client-go/kubernetes/typed"

	targetMethods := []string{"Create", "Update", "Patch", "Delete", "Get", "List", "Watch", "DeleteCollection"}

	outputFile := "methods.tmp"
	outFile, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	err = filepath.Walk(myrootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, "fake") {
			return nil
		}

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			return err
		}

		packagePath := filepath.Dir(path)
		packagePath = strings.TrimPrefix(packagePath, myrootDir+"/") // Remove rootDir prefix
		packagePath = strings.ReplaceAll(packagePath, "\\", "/")
		packagePath = "k8s.io/client-go/kubernetes/typed/" + packagePath

		ast.Inspect(node, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Recv != nil {
				funcName := fn.Name.Name

				if contains(targetMethods, funcName) {
					recv := ""
					if len(fn.Recv.List) > 0 {
						switch t := fn.Recv.List[0].Type.(type) {
						case *ast.StarExpr:
							if ident, ok := t.X.(*ast.Ident); ok {
								recv = ident.Name
							}
						case *ast.Ident:
							recv = t.Name
						}
					}

					if recv != "" {
						fullPath := "(*" + packagePath + "." + recv + ")." + funcName
						outFile.WriteString(fullPath + "\n")
					}
				}
			}
			return true
		})

		return nil
	})

	if err != nil {
		panic(err)
	}

}
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
func conversion() {
	filename := rootDir + "pkg/controller/replication/conversion.go"

	src, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, filename, src, parser.AllErrors)
	if err != nil {
		fmt.Printf("Error parsing file: %v\n", err)
		return
	}

	targetReceivers := map[string]struct{}{
		"conversionClient":       {},
		"conversionAppsV1Client": {},
	}

	unusedImports := map[string]struct{}{
		"k8s.io/apimachinery/pkg/watch":                       {},
		"k8s.io/client-go/applyconfigurations/apps/v1":        {},
		"k8s.io/client-go/applyconfigurations/autoscaling/v1": {},
		"k8s.io/api/autoscaling/v1":                           {},
		"errors":                                              {},
		"k8s.io/apimachinery/pkg/types":                       {},
	}

	var methodsToRemove []*ast.FuncDecl
	ast.Inspect(node, func(n ast.Node) bool {
		funcDecl, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		if funcDecl.Recv == nil || len(funcDecl.Recv.List) == 0 {
			return true
		}

		recvExpr := funcDecl.Recv.List[0].Type
		var recvTypeName string
		switch recvType := recvExpr.(type) {
		case *ast.Ident:
			recvTypeName = recvType.Name
		case *ast.StarExpr:
			if ident, ok := recvType.X.(*ast.Ident); ok {
				recvTypeName = ident.Name
			}
		}

		if _, ok := targetReceivers[recvTypeName]; ok {
			methodsToRemove = append(methodsToRemove, funcDecl)
		}
		return true
	})

	if len(methodsToRemove) == 0 {
		fmt.Println("No methods found for the specified receiver types.")
	} else {
		node.Decls = removeMethods(node.Decls, methodsToRemove)
	}

	node.Decls = removeUnusedImports(node.Decls, unusedImports)

	var output bytes.Buffer
	err = printer.Fprint(&output, fset, node)
	if err != nil {
		fmt.Printf("Error printing modified AST: %v\n", err)
		return
	}

	err = os.WriteFile(filename, output.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	//fmt.Println("Methods and unused imports have been removed and file updated.")
}
func removeLinesFromFile(filePath string, stringsToRemove []string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	tempFilePath := filePath + ".tmp"
	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	writer := bufio.NewWriter(tempFile)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		shouldRemove := false
		for _, str := range stringsToRemove {
			if strings.Contains(line, str) {
				shouldRemove = true
				break
			}
		}

		if !shouldRemove {
			_, err := writer.WriteString(line + "\n")
			if err != nil {
				return fmt.Errorf("failed to write to temporary file: %w", err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	writer.Flush()
	tempFile.Close()

	file.Close()

	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to remove original file: %w", err)
	}
	if err := os.Rename(tempFilePath, filePath); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}
func removeMethods(decls []ast.Decl, methodsToRemove []*ast.FuncDecl) []ast.Decl {
	var newDecls []ast.Decl
	for _, decl := range decls {
		if isTargetMethod(decl, methodsToRemove) {
			continue
		}
		newDecls = append(newDecls, decl)
	}
	return newDecls
}

func isTargetMethod(decl ast.Decl, methodsToRemove []*ast.FuncDecl) bool {
	funcDecl, ok := decl.(*ast.FuncDecl)
	if !ok {
		return false
	}
	for _, target := range methodsToRemove {
		if funcDecl == target {
			return true
		}
	}
	return false
}

func removeUnusedImports(decls []ast.Decl, unusedImports map[string]struct{}) []ast.Decl {
	var newDecls []ast.Decl
	for _, decl := range decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.IMPORT {
			newDecls = append(newDecls, decl)
			continue
		}

		var newSpecs []ast.Spec
		for _, spec := range genDecl.Specs {
			importSpec, ok := spec.(*ast.ImportSpec)
			if !ok {
				continue
			}

			path := strings.Trim(importSpec.Path.Value, `"`)

			if _, ok := unusedImports[path]; ok {
				continue
			}

			newSpecs = append(newSpecs, spec)
		}

		if len(newSpecs) > 0 {
			genDecl.Specs = newSpecs
			newDecls = append(newDecls, genDecl)
		}
	}
	return newDecls
}
func handler() {
	inputData := map[string]map[string]string{
		rootDir + "pkg/controller/serviceaccount/serviceaccounts_controller.go": {
			"syncHandler": "syncNamespace",
		},
		rootDir + "pkg/controller/certificates/rootcacertpublisher/publisher.go": {
			"syncHandler": "syncNamespace",
		},
		rootDir + "pkg/controller/job/job_controller.go": {
			"syncHandler":         "syncJob",
			"updateStatusHandler": "updateJobStatus",
		},
		rootDir + "pkg/controller/resourcequota/resource_quota_controller.go": {
			"syncHandler": "syncResourceQuotaFromKey",
		},
		rootDir + "pkg/controller/clusterroleaggregation/clusterroleaggregation_controller.go": {
			"syncHandler": "syncClusterRole",
		},
		rootDir + "pkg/controller/daemon/daemon_controller.go": {
			"syncHandler": "syncDaemonSet",
		},
		rootDir + "pkg/controller/deployment/deployment_controller.go": {
			"syncHandler": "syncDeployment",
		},
		rootDir + "pkg/controller/nodelifecycle/node_lifecycle_controller.go": {
			"enterPartialDisruptionFunc": "ReducedQPSFunc",
			"enterFullDisruptionFunc":    "HealthyQPSFunc",
			"computeZoneStateFunc":       "ComputeZoneState",
		},
		rootDir + "pkg/controller/replicaset/replica_set.go": {
			"syncHandler": "syncReplicaSet",
		},
	}

	for fileName, methodMap := range inputData {
		//fmt.Printf("Processing file: %s\n", fileName)
		if err := processFile(fileName, methodMap); err != nil {
			fmt.Fprintf(os.Stderr, "Error processing file %s: %v\n", fileName, err)
		}
	}

	fmt.Println("Processing completed.")
}
func processFile(filePath string, methodMap map[string]string) error {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, filePath, src, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	updated := false

	ast.Inspect(node, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if replacement, exists := methodMap[selectorExpr.Sel.Name]; exists {
					//fmt.Printf("Replacing %s with %s in file %s\n", selectorExpr.Sel.Name, replacement, filePath)

					selectorExpr.Sel.Name = replacement
					updated = true
				}
			}
		}
		return true
	})

	if updated {
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		defer file.Close()

		if err := printer.Fprint(file, fset, node); err != nil {
			return fmt.Errorf("failed to print modified file: %w", err)
		}
	}

	return nil
}
func run() {
	if err := processDir(rootDir + "pkg/controller"); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
func processDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			if err := processFile_Run(path); err != nil {
				return fmt.Errorf("error processing file %s: %w", path, err)
			}
		}
		return nil
	})
}

func processFile_Run(filename string) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	updated := false
	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil {
			if fn.Name.Name == "Run" {
				updated = modifyRunMethod(fn, filename) || updated
			}
		}
		return true
	})

	if updated {
		file, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("failed to open file for writing: %w", err)
		}
		defer file.Close()

		if err := printer.Fprint(file, fset, node); err != nil {
			return fmt.Errorf("failed to write updated code: %w", err)
		}
	}

	return nil
}

func modifyRunMethod(fn *ast.FuncDecl, filename string) bool {
	updated := false

	fn.Body.List = processStatements(fn.Body.List, &updated, filename)

	return updated
}

func processStatements(stmts []ast.Stmt, updated *bool, filename string) []ast.Stmt {
	var newStmts []ast.Stmt

	for _, stmt := range stmts {
		if goStmt, ok := stmt.(*ast.GoStmt); ok {
			call := goStmt.Call
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "UntilWithContext" && len(call.Args) == 3 {
					arg1 := call.Args[0]
					arg2 := call.Args[1]
					newStmt := &ast.ExprStmt{
						X: &ast.CallExpr{
							Fun:  arg2,
							Args: []ast.Expr{arg1},
						},
					}
					newStmts = append(newStmts, newStmt)
					*updated = true
				} else if sel.Sel.Name == "Until" && len(call.Args) == 3 {
					arg1 := call.Args[0]
					newStmt := &ast.ExprStmt{
						X: &ast.CallExpr{
							Fun: arg1,
						},
					}
					newStmts = append(newStmts, newStmt)
					*updated = true
				}

			}
		}

		newStmts = append(newStmts, stmt)

		switch s := stmt.(type) {
		case *ast.BlockStmt:
			s.List = processStatements(s.List, updated, filename)
		case *ast.IfStmt:
			s.Body.List = processStatements(s.Body.List, updated, filename)
			if s.Else != nil {
				if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
					elseBlock.List = processStatements(elseBlock.List, updated, filename)
				}
			}
		case *ast.ForStmt:
			fmt.Println(filename)
			s.Body.List = processStatements(s.Body.List, updated, filename)
		case *ast.RangeStmt:
			s.Body.List = processStatements(s.Body.List, updated, filename)
		}
	}

	return newStmts
}
func slowstart() {
	filePath := rootDir + "pkg/controller/replicaset/replica_set.go"

	slowStartBatchName := "slowStartBatch"
	if err := replaceFunctionBody(filePath, slowStartBatchName); err != nil {
		fmt.Fprintf(os.Stderr, "Error replacing function body for %s: %v\n", slowStartBatchName, err)
		os.Exit(1)
	}

	manageReplicasName := "manageReplicas"
	newCode := `err := rsc.podControl.CreatePods(ctx, rs.Namespace, &rs.Spec.Template, rs, metav1.NewControllerRef(rs, rsc.GroupVersionKind))`
	if err := addLineToFunction(filePath, manageReplicasName, newCode); err != nil {
		fmt.Fprintf(os.Stderr, "Error modifying function %s: %v\n", manageReplicasName, err)
		os.Exit(1)
	}
	removeLineWithString(filePath, "k8s.io/utils/integer")
	fmt.Println("init successfully.")
}

func removeLineWithString(filePath string, targetString string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, targetString) {
			found = true
			continue
		}
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	if !found {
		//fmt.Printf("string '%s' not found in file %s\n", targetString, filePath)
		return nil
	}

	file, err = os.Create(filePath)
	if err != nil {
		return fmt.Errorf("cannot create file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("error writing to file: %v", err)
		}
	}

	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("error flushing buffer: %v", err)
	}

	//fmt.Printf("successfully removed lines containing '%s' from file %s\n", targetString, filePath)
	return nil
}

func replaceFunctionBody(filePath string, functionName string) error {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, filePath, src, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	updated := false

	ast.Inspect(node, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			if funcDecl.Name.Name == functionName {
				//fmt.Printf("Modifying function %s in file %s\n", functionName, filePath)

				returnStmt := &ast.ReturnStmt{
					Results: []ast.Expr{
						&ast.BasicLit{
							Kind:  token.INT,
							Value: "1",
						},
						&ast.Ident{
							Name: "nil",
						},
					},
				}

				funcDecl.Body = &ast.BlockStmt{
					List: []ast.Stmt{returnStmt},
				}

				updated = true
			}
		}
		return true
	})

	if updated {
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		defer file.Close()

		if err := printer.Fprint(file, fset, node); err != nil {
			return fmt.Errorf("failed to print modified file: %w", err)
		}
	}

	return nil
}

func addLineToFunction(filePath string, functionName string, newCode string) error {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, filePath, src, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	updated := false

	ast.Inspect(node, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			if funcDecl.Name.Name == functionName {
				//fmt.Printf("Modifying function %s in file %s\n", functionName, filePath)

				newStmt, err := parseStmt(newCode)
				if err != nil {
					fmt.Printf("Failed to parse new code: %v\n", err)
					return false
				}

				funcDecl.Body.List = append([]ast.Stmt{newStmt}, funcDecl.Body.List...)
				updated = true
			}
		}
		return true
	})

	if updated {
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		defer file.Close()

		if err := printer.Fprint(file, fset, node); err != nil {
			return fmt.Errorf("failed to print modified file: %w", err)
		}
	}

	return nil
}

func parseStmt(stmt string) (ast.Stmt, error) {
	src := fmt.Sprintf("package main\nfunc temp() {\n%s\n}", stmt)

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, "", src, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("failed to parse statement: %w", err)
	}

	if len(node.Decls) == 0 {
		return nil, fmt.Errorf("no declarations found")
	}
	if funcDecl, ok := node.Decls[0].(*ast.FuncDecl); ok {
		if len(funcDecl.Body.List) == 0 {
			return nil, fmt.Errorf("no statements found in function body")
		}
		return funcDecl.Body.List[0], nil
	}

	return nil, fmt.Errorf("failed to extract statement")
}
func Before() {
	addMethodIfNeed()
	filePath := rootDir + "pkg/controller/volume/attachdetach/attach_detach_controller.go"

	stringsToRemove := []string{
		"go adc.reconciler.Run(ctx)",
		"go adc.desiredStateOfWorldPopulator.Run(ctx)",
	}

	if err := removeLinesFromFile(filePath, stringsToRemove); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	collect()
	conversion()
	handler()
	run()
	slowstart()
}
func rsc(resA, resB, verbA, verbB string, data *[]string) {
	if resA == "replicaSets" {
		*data = append(*data, verbA+" replicationcontrollers"+" --> "+verbB+" "+resB)
	}
}

//	func up(resA, resB, verbA, verbB string, data *[]string) bool {
//		if verbB == "patch" {
//			verbB = "update"
//			*data = append(*data, verbA+" "+resA+" --> "+verbB+" "+resB)
//			return true
//		}
//		return false
//	}
func removeDuplicateLines(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	seenLines := make(map[string]bool)

	uniqueLines := []string{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !seenLines[line] {
			seenLines[line] = true
			uniqueLines = append(uniqueLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	file.Close()

	writeFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer writeFile.Close()

	writer := bufio.NewWriter(writeFile)
	for _, line := range uniqueLines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	writer.Flush()

	return nil
}

func readMappings(fileName string) (map[string][]string, error) {
	mappings := make(map[string][]string)
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, "-->")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format: %s", line)
		}
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		mappings[left] = append(mappings[left], right)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	return mappings, nil
}

func deriveMappings(mappings map[string][]string) map[string][]string {
	newMappings := make(map[string][]string)
	for key, midValues := range mappings {
		if strings.Contains(key, "/") {
			continue
		}
		for _, midValue := range midValues {
			if targets, exists := mappings[midValue]; exists {
				for _, target := range targets {
					newMappings[key] = append(newMappings[key], target)
				}
			}
		}
	}
	return newMappings
}

func mergeMappings(original, derived map[string][]string) map[string][]string {
	merged := make(map[string][]string)
	for key, values := range original {
		merged[key] = append(merged[key], values...)
	}
	for key, values := range derived {
		merged[key] = append(merged[key], values...)
	}
	for key, values := range merged {
		merged[key] = removeDuplicates2(values)
	}
	return merged
}

func removeDuplicates2(items []string) []string {
	unique := make(map[string]struct{})
	result := []string{}
	for _, item := range items {
		if _, exists := unique[item]; !exists {
			unique[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func writeMappings(fileName string, mappings map[string][]string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for key, values := range mappings {
		for _, value := range values {
			_, err := writer.WriteString(fmt.Sprintf("%s --> %s\n", key, value))
			if err != nil {
				return fmt.Errorf("failed to write to file: %w", err)
			}
		}
	}
	writer.Flush()
	return nil
}

func multiRef(inputFileName, outputFileName string) {
	mappings, err := readMappings(inputFileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading mappings: %v\n", err)
		os.Exit(1)
	}

	derivedMappings := deriveMappings(mappings)
	finalMappings := mergeMappings(mappings, derivedMappings)

	if err := writeMappings(outputFileName, finalMappings); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing mappings: %v\n", err)
		os.Exit(1)
	}
}
func DeleteTmpFiles(fileNames []string) error {
	for _, fileName := range fileNames {
		err := os.Remove(fileName)
		if err != nil {
			return fmt.Errorf("failed to delete file %s: %w", fileName, err)
		}
	}
	return nil
}
func ReadFiles(funcFileName string) []string {
	var targetFuncs []string
	funcFile, _ := os.Open(funcFileName)
	defer funcFile.Close()
	scanner := bufio.NewScanner(funcFile)
	for scanner.Scan() {
		line := scanner.Text()
		targetFuncs = append(targetFuncs, line)
	}
	return targetFuncs
}

func addMethodIfNeed() {
	if !checkVersion(rootDir) {
		fmt.Println("v1")
		return
	}
	// if len(os.Args) < 2 {
	// 	fmt.Println("Usage: go run main.go <path_to_clientgo_typed>")
	// 	fmt.Println("Example: go run main.go /path/to/k8s/staging/src/k8s.io/client-go/kubernetes/typed")
	// 	os.Exit(1)
	// }

	// rootPath := os.Args[1]

	// fmt.Printf("Analyzing path: %s\n", rootPath)

	interfaces, structs, err := analyzeDirectory(rootDir)
	if err != nil {
		fmt.Printf("Error analyzing directory: %v\n", err)
		os.Exit(1)
	}

	//fmt.Printf("Found %d interfaces and %d structs with gentype embedding\n", len(interfaces), len(structs))

	fileToInterfaces := make(map[string][]InterfaceInfo)
	fileToStructs := make(map[string][]StructInfo2)

	for _, interfaceInfo := range interfaces {
		fileToInterfaces[interfaceInfo.File] = append(fileToInterfaces[interfaceInfo.File], interfaceInfo)
	}

	for _, structInfo := range structs {
		fileToStructs[structInfo.File] = append(fileToStructs[structInfo.File], structInfo)
	}

	for filePath, fileInterfaces := range fileToInterfaces {
		fileStructs, hasStructs := fileToStructs[filePath]

		for _, interfaceInfo := range fileInterfaces {
			if hasStructs {
				for _, structInfo := range fileStructs {
					filteredInterface := filterInterfaceMethods(interfaceInfo, structInfo.EmbedTypes)
					if len(filteredInterface.Methods) == 0 {
						continue
					}

					err := addMethodsToStruct(structInfo, filteredInterface)
					if err != nil {
						fmt.Printf("Error adding methods to struct %s: %v\n", structInfo.Name, err)
					} else {
						// fmt.Printf("Added %d methods from interface %s to struct %s in file %s\n",
						// 	len(filteredInterface.Methods), interfaceInfo.Name, structInfo.Name, filePath)
					}
				}
			} else {
				//fmt.Printf("Interface %s in file %s: no matching gentype struct found\n", interfaceInfo.Name, filePath)
			}
		}
	}

	//fmt.Println("Method addition completed!")
}

func analyzeDirectory(rootPath string) ([]InterfaceInfo, []StructInfo2, error) {
	var interfaces []InterfaceInfo
	var structs []StructInfo2

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") ||
			strings.Contains(path, "generated") ||
			strings.Contains(path, "fake") {
			return nil
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			fmt.Printf("Warning: failed to parse %s: %v\n", path, err)
			return nil
		}

		fileInterfaces := extractInterfaces(file, path)
		interfaces = append(interfaces, fileInterfaces...)

		fileStructs := extractStructsWithGentype(file, path)
		structs = append(structs, fileStructs...)

		return nil
	})

	return interfaces, structs, err
}

func extractInterfaces(file *ast.File, filePath string) []InterfaceInfo {
	var interfaces []InterfaceInfo

	ast.Inspect(file, func(n ast.Node) bool {
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.TYPE {
			for _, spec := range genDecl.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok {
					if interfaceType, ok := typeSpec.Type.(*ast.InterfaceType); ok {
						methods := extractMethodsFromInterface(interfaceType)
						if len(methods) > 0 {
							interfaces = append(interfaces, InterfaceInfo{
								Name:    typeSpec.Name.Name,
								Methods: methods,
								File:    filePath,
							})
						}
					}
				}
			}
		}
		return true
	})

	return interfaces
}

func extractMethodsFromInterface(interfaceType *ast.InterfaceType) []MethodInfo {
	var methods []MethodInfo

	for _, method := range interfaceType.Methods.List {
		if len(method.Names) > 0 {
			if funcType, ok := method.Type.(*ast.FuncType); ok {
				methodInfo := MethodInfo{
					Name: method.Names[0].Name,
				}

				if funcType.Params != nil {
					for _, param := range funcType.Params.List {
						paramType := getTypeString(param.Type)
						if len(param.Names) > 0 {
							for _, name := range param.Names {
								methodInfo.Params = append(methodInfo.Params, Param{
									Name: name.Name,
									Type: paramType,
								})
							}
						} else {
							methodInfo.Params = append(methodInfo.Params, Param{
								Name: "",
								Type: paramType,
							})
						}
					}

					if funcType.Params.List != nil && len(funcType.Params.List) > 0 {
						lastParam := funcType.Params.List[len(funcType.Params.List)-1]
						if _, ok := lastParam.Type.(*ast.Ellipsis); ok {
							methodInfo.IsVariadic = true
						}
					}
				}

				if funcType.Results != nil {
					for _, result := range funcType.Results.List {
						resultType := getTypeString(result.Type)
						if len(result.Names) > 0 {
							for _, name := range result.Names {
								methodInfo.Results = append(methodInfo.Results, Param{
									Name: name.Name,
									Type: resultType,
								})
							}
						} else {
							methodInfo.Results = append(methodInfo.Results, Param{
								Name: "",
								Type: resultType,
							})
						}
					}
				}

				methods = append(methods, methodInfo)
			}
		}
	}

	return methods
}

func extractStructsWithGentype(file *ast.File, filePath string) []StructInfo2 {
	var structs []StructInfo2

	ast.Inspect(file, func(n ast.Node) bool {
		if genDecl, ok := n.(*ast.GenDecl); ok && genDecl.Tok == token.TYPE {
			for _, spec := range genDecl.Specs {
				if typeSpec, ok := spec.(*ast.TypeSpec); ok {
					if structType, ok := typeSpec.Type.(*ast.StructType); ok {
						structName := typeSpec.Name.Name
						for _, field := range structType.Fields.List {
							if len(field.Names) == 0 {
								typeStr := getTypeString(field.Type)
								if strings.Contains(filePath, "pod") || strings.Contains(filePath, "node") {
									fmt.Printf("Debug: struct %s in file %s has embedded field: %s\n", structName, filePath, typeStr)
								}
							}
						}

						if hasEmbed, embedTypes := hasGentypeEmbedding(structType); hasEmbed {
							//fmt.Printf("found gentype embedded struct: %s in file %s, embedded types: %v\n", structName, filePath, embedTypes)
							structs = append(structs, StructInfo2{
								Name:       typeSpec.Name.Name,
								File:       filePath,
								EmbedGen:   true,
								EmbedTypes: embedTypes,
							})
						}
					}
				}
			}
		}
		return true
	})

	return structs
}

func hasGentypeEmbedding(structType *ast.StructType) (bool, []string) {
	var embedTypes []string

	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 {
			typeStr := getTypeString(field.Type)
			if strings.Contains(typeStr, "gentype.Client") {
				if strings.Contains(typeStr, "gentype.ClientWithListAndApply") {
					embedTypes = append(embedTypes, "ClientWithListAndApply")
				} else if strings.Contains(typeStr, "gentype.ClientWithList") {
					embedTypes = append(embedTypes, "ClientWithList")
				} else if strings.Contains(typeStr, "gentype.ClientWithApply") {
					embedTypes = append(embedTypes, "ClientWithApply")
				} else if strings.Contains(typeStr, "gentype.Client") {
					embedTypes = append(embedTypes, "Client")
				}
			}
		}
	}

	return len(embedTypes) > 0, embedTypes
}

func filterInterfaceMethods(interfaceInfo InterfaceInfo, embedTypes []string) InterfaceInfo {
	clientMethods := map[string][]string{
		"Client":                 []string{"Create", "Get", "Update", "UpdateStatus", "Delete", "Patch", "Watch"},
		"ClientWithList":         []string{"Create", "Get", "Update", "UpdateStatus", "Delete", "Patch", "Watch", "List", "DeleteCollection"},
		"ClientWithApply":        []string{"Create", "Get", "Update", "UpdateStatus", "Delete", "Patch", "Watch", "Apply", "ApplyStatus"},
		"ClientWithListAndApply": []string{"Create", "Get", "Update", "UpdateStatus", "Delete", "Patch", "Watch", "List", "DeleteCollection", "Apply", "ApplyStatus"},
	}

	targetMethods := []string{"Create", "Get", "Patch", "Update", "Delete", "List", "Watch", "DeleteCollection"}

	var supportedMethods []string
	for _, embedType := range embedTypes {
		if methods, exists := clientMethods[embedType]; exists {
			supportedMethods = append(supportedMethods, methods...)
		}
	}

	var filteredMethods []MethodInfo
	for _, method := range interfaceInfo.Methods {
		if contains(targetMethods, method.Name) && contains(supportedMethods, method.Name) {
			filteredMethods = append(filteredMethods, method)
		}
	}

	return InterfaceInfo{
		Name:    interfaceInfo.Name,
		Methods: filteredMethods,
		File:    interfaceInfo.File,
	}
}

// func contains(slice []string, item string) bool {
// 	for _, s := range slice {
// 		if s == item {
// 			return true
// 		}
// 	}
// 	return false
// }

func getTypeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + getTypeString(t.X)
	case *ast.SelectorExpr:
		return getTypeString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + getTypeString(t.Elt)
	case *ast.MapType:
		return "map[" + getTypeString(t.Key) + "]" + getTypeString(t.Value)
	case *ast.Ellipsis:
		return "..." + getTypeString(t.Elt)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	case *ast.IndexExpr:
		return getTypeString(t.X) + "[" + getTypeString(t.Index) + "]"
	case *ast.IndexListExpr:
		var params []string
		for _, index := range t.Indices {
			params = append(params, getTypeString(index))
		}
		return getTypeString(t.X) + "[" + strings.Join(params, ", ") + "]"
	default:
		return "unknown"
	}
}

func addMethodsToStruct(structInfo StructInfo2, interfaceInfo InterfaceInfo) error {
	content, err := ioutil.ReadFile(structInfo.File)
	if err != nil {
		return err
	}

	// fset := token.NewFileSet()
	// file, err := parser.ParseFile(fset, structInfo.File, content, parser.AllErrors)
	// if err != nil {
	// 	return err
	// }

	var methodsCode []string
	for _, method := range interfaceInfo.Methods {
		methodCode := generateMethodCode(structInfo.Name, method)
		methodsCode = append(methodsCode, methodCode)
	}

	if len(methodsCode) == 0 {
		return nil
	}

	methodsStr := "\n// Methods from interface " + interfaceInfo.Name + "\n"
	methodsStr += strings.Join(methodsCode, "\n\n")
	methodsStr += "\n"

	newContent := string(content) + methodsStr
	return ioutil.WriteFile(structInfo.File, []byte(newContent), 0644)
}

func generateMethodCode(structName string, method MethodInfo) string {
	var code strings.Builder

	code.WriteString("func (c *")
	code.WriteString(structName)
	code.WriteString(") ")
	code.WriteString(method.Name)
	code.WriteString("(")

	var params []string
	for i, param := range method.Params {
		paramStr := ""
		if param.Name != "" {
			paramStr += param.Name + " "
		} else {
			paramStr += fmt.Sprintf("arg%d ", i)
		}
		paramStr += param.Type
		params = append(params, paramStr)
	}
	code.WriteString(strings.Join(params, ", "))
	code.WriteString(")")

	if len(method.Results) > 0 {
		code.WriteString(" (")
		var results []string
		for i, result := range method.Results {
			resultStr := ""
			if result.Name != "" {
				resultStr += result.Name + " "
			} else if len(method.Results) > 1 {
				resultStr += fmt.Sprintf("r%d ", i)
			}
			resultStr += result.Type
			results = append(results, resultStr)
		}
		code.WriteString(strings.Join(results, ", "))
		code.WriteString(")")
	}

	code.WriteString(" {\n")

	if len(method.Results) > 0 {
		code.WriteString("\t")
		if len(method.Results) == 1 {
			code.WriteString("return nil")
			//code.WriteString(getZeroValue(method.Results[0].Type))
		} else {
			code.WriteString("return ")
			// var zeroValues []string
			// for _, result := range method.Results {
			// 	zeroValues = append(zeroValues, getZeroValue(result.Type))
			// }
			// code.WriteString(strings.Join(zeroValues, ", "))
		}
		code.WriteString("\n")
	}

	code.WriteString("}")

	return code.String()
}

func getZeroValue(typeStr string) string {
	if strings.HasPrefix(typeStr, "*") || strings.HasPrefix(typeStr, "[]") || strings.HasPrefix(typeStr, "map[") {
		return "nil"
	}

	switch typeStr {
	case "string":
		return `""`
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return "0"
	case "float32", "float64":
		return "0.0"
	case "bool":
		return "false"
	case "error":
		return "nil"
	default:
		if strings.Contains(typeStr, "interface") {
			return "nil"
		}
		if strings.Contains(typeStr, ".") {
			return typeStr + "{}"
		}
		return "nil"
	}
}

func checkVersion(rootPath string) bool {
	genTypePath := rootPath + "staging/src/k8s.io/client-go/gentype/type.go"
	_, err := os.Stat(genTypePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		fmt.Printf("error checking file %s: %v\n", genTypePath, err)
		return false
	}
	return true
}
