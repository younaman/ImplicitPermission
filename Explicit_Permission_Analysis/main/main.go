package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/tools/go/packages"
)

// "golang.org/x/tools/go/callgraph/cha"
// "golang.org/x/tools/go/ssa/ssautil"
// "golang.org/x/tools/go/pointer"
var (
	whiteList    = []string{"*k8s.io", "k8s.io"}
	resources    = []node{}
	resourcesSet = map[string][]node{}
	resourceMap  = map[string]*types.Struct{}
	astFiles     []*ast.File
	notFound     = map[string]string{}
	registerApi  = map[string]string{}
	res          = map[string]map[string]string{}
	RegistryPkgs []*packages.Package
	allRes       = map[string]bool{}
	tupleRes     = []string{}
	result       = map[string][]string{}
	globalVar    = map[string]string{}
)

type node struct {
	resource ResourceInfo
	next     *node
}

type ResourceInfo struct {
	fullName   string
	typeStruct *types.Struct `json:"fields" yaml:"fields"`
}

func loadPackagesRecursive(dir string) error {
	// if !strings.Contains(dir, "registry") || !strings.Contains(dir, "vendor") {
	// 	return nil
	// }
	cfg := &packages.Config{
		Mode: packages.LoadSyntax,
		Dir:  dir,
	}

	// Load all packages in the root directory and its subdirectories
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return err
	}
	for _, pkg := range pkgs {
		RegistryPkgs = append(RegistryPkgs, pkg)
	}
	subdirs, err := getSubDirs(dir)
	if len(subdirs) == 0 {
		return nil
	}
	for _, dir1 := range subdirs {
		loadPackagesRecursive(dir1)
	}
	return nil
}
func getSubDirs(root string) ([]string, error) {
	var subDirs []string

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subDirs = append(subDirs, filepath.Join(root, entry.Name()))
		}
	}

	return subDirs, nil
}

func run() (interface{}, error) {
	resultFile := os.Args[2]
	file, err := os.OpenFile(resultFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil, nil
	}
	defer file.Close()
	os.Stdout = file
	rootDir := os.Args[1]
	//rootDir := "/root/codes/go/k8s/kubernetes/pkg/registry" //"/root/codes/go/k8s/kubernetes/staging/src/k8s.io"
	err = loadPackagesRecursive(rootDir)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(RegistryPkgs)
	a()
	for k, v := range result {
		fmt.Println(k, v)
	}
	return nil, nil

}
func main() {
	//singlechecker.Main(analyzer)
	run()
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
	for _, i := range tupleRes {
		if !allRes[i] {
			fmt.Println("[Tuple]", i)
		}

	}
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
							if _, ok := res[resource]; !ok {
								//res[resource] = []string{}
								//fmt.Println(resource)
								res[resource] = map[string]string{}
							}
							//fmt.Println(resource)
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
							fullName := resource + subResource
							switch t := typ.(type) {
							case *types.Pointer:
								allRes[fullName] = true
								result[fullName] = printMethods(typ)
								//fmt.Println("[Pointer]", fullName, "["+typ.String()+"]")
							case *types.Tuple:
								if allRes[fullName] {
									continue
								}
								tupleRes = append(tupleRes, fullName)
								// fmt.Println("[Tuple]", fullName, "["+t.At(0).String()+"]")
								// fmt.Println(reflect.TypeOf(t.At(0)))
								// printMethods(types.NewPointer(t.At(0).Type()))
							default:
								fmt.Println("[other]")
								fmt.Println(reflect.TypeOf(t))
							}
							//fmt.Println("=========================================")
							//fmt.Printf("Expression: %s, Type: %s\n", pkg.Fset.Position(expr.Pos()), typ.String())
						}
						// switch t := expr.(type) {
						// case *ast.CallExpr:
						// 	fmt.Println("[call]")
						// 	fmt.Println(resource)
						// 	//fmt.Println((t.Fun.(*ast.SelectorExpr).Sel))
						// 	fmt.Println("--------")
						// case *ast.Ident:
						// 	fmt.Println("[ident]")
						// 	fmt.Println(resource)
						// 	//fmt.Println(t.Obj)
						// 	fmt.Println("--------")
						// case *ast.SelectorExpr:
						// 	fmt.Println("[sel]")
						// 	fmt.Println(resource)
						// 	//fmt.Println(t.Sel)
						// 	fmt.Println("--------")
						// default:
						// 	fmt.Println("[other]")
						// 	fmt.Println("[", reflect.TypeOf(t), "]")
						// 	fmt.Println("--------------------------")
						// }
						//fmt.Println(reflect.TypeOf(expr))
						// ast.Inspect(expr, func(n ast.Node) bool {
						// 
						// 	if ident, ok := n.(*ast.Ident); ok {
						// 		// if strings.Contains(ident.Name, "C2") {
						// 		// 	fmt.Println(ident.Obj)
						// 		// }
						// 		fmt.Printf("%s\n", ident.Obj)
						// 	}
						// 	return true
						// })
					}
				}
				return true
			})
		}

	}
}
func printMethods(typ types.Type) []string {
	//fmt.Println(typ.String())
	methodSet := types.NewMethodSet(typ)
	//fmt.Println(methodSet)
	verbs := []string{"Get", "Update", "Watch", "Create", "Delete", "DeleteCollection", "List"}
	result := []string{}
	flag := 0
	for i := 0; i < methodSet.Len(); i++ {
		method := methodSet.At(i)
		methodName := method.Obj().Name()
		for _, verb := range verbs {
			if methodName == verb {
				result = append(result, methodName)
				if methodName == "Update" || methodName == "Get" {
					flag += 1

				}
				//fmt.Println(methodName)
			}
		}
		if methodName == "Connect" {
			sName := typ.String()[strings.LastIndex(typ.String(), ".")+1:]
			//fmt.Println(sName)
			verbs := findVerbs(sName)
			result = append(result, verbs...)
		}

	}
	if flag == 2 {
		result = append(result, "Patch")
	}
	return result
}
func findVerbs(sName string) []string {
	result := []string{}
	for _, pkg := range RegistryPkgs {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if funcDecl, ok := decl.(*ast.FuncDecl); ok {
					if funcDecl.Name.String() == "ConnectMethods" {
						rt := ""
						flag := false
						ast.Inspect(funcDecl, func(n ast.Node) bool {
							if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
								if starExpr, ok := funcDecl.Recv.List[0].Type.(*ast.StarExpr); ok {
									if ident, ok := starExpr.X.(*ast.Ident); ok && ident.Name == sName {
										if returnStmt, ok := n.(*ast.ReturnStmt); ok {
											for _, result := range returnStmt.Results {
												if ident, ok := result.(*ast.Ident); ok {
													rt = ident.Name
												}
											}
											_, ok := globalVar[rt]
											if !ok {
												findVar()
											}
											rtValue := globalVar[rt]
											if strings.Contains(rtValue, "GET") {
												result = append(result, "Get")
											}
											if strings.Contains(rtValue, "POST") {
												result = append(result, "Create")
											}
											if strings.Contains(rtValue, "PUT") {
												result = append(result, "Update")
											}
											if strings.Contains(rtValue, "PATCH") {
												result = append(result, "Patch")
											}
											if strings.Contains(rtValue, "DELETE") {
												result = append(result, "Delete")
											}
											flag = true
											return false
										}
									}
								}

							}

							return true
						})
						if flag {
							return result
						}
					}
				}

			}
		}
	}
	//fmt.Println(funcDecl.Name.String())

	return result

}
func findVar() {
	for _, pkg := range RegistryPkgs {
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if decl, ok := n.(*ast.GenDecl); ok && decl.Tok == token.VAR {
					if decl.Lparen == token.NoPos { 
						for _, spec := range decl.Specs {
							if vspec, ok := spec.(*ast.ValueSpec); ok {
								for i, name := range vspec.Names {
									if len(vspec.Values) > i {
										globalVar[name.Name] = exprToString(vspec.Values[i])
									}

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
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value
	case *ast.CompositeLit:
		if len(e.Elts) > 0 {
			var values []string
			for _, elt := range e.Elts {
				values = append(values, exprToString(elt))
			}
			return "{" + strings.Join(values, ", ") + "}"
		}
		return "empty composite literal"
	default:
		return "???"
	}
}
