package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/ioutil"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
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
)

type node struct {
	resource ResourceInfo
	next     *node
}

type ResourceInfo struct {
	fullName   string
	typeStruct *types.Struct `json:"fields" yaml:"fields"`
}

func loadAllDeps(initial []*packages.Package, visited map[string]*packages.Package) {
	for _, pkg := range initial {
		if _, done := visited[pkg.PkgPath]; !done {
			visited[pkg.PkgPath] = pkg
			importsAsSlice := make([]*packages.Package, 0, len(pkg.Imports))
			for _, imp := range pkg.Imports {
				importsAsSlice = append(importsAsSlice, imp)
			}
			loadAllDeps(importsAsSlice, visited)
		}
	}
}

func buildSSA(fset *token.FileSet, visited map[string]*packages.Package) *ssa.Program {
	// 创建一个新的 SSA 程序
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))

	// 首先为所有导入的包创建 SSA 包
	ssaPkgs := make(map[*packages.Package]*ssa.Package)
	for _, pkg := range visited {
		ssaPkg := prog.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, false)
		ssaPkgs[pkg] = ssaPkg
	}

	// 确保所有包都建立了 SSA 形式
	for _, ssaPkg := range ssaPkgs {
		ssaPkg.Build()
	}

	return prog
}
func parseAndTypeCheck(filename string) (*ast.File, *types.Package, error) {
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, filename)
	if err != nil || len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("error loading packages: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, nil, fmt.Errorf("errors occurred while loading package")
	}
	return pkgs[0].Syntax[0], pkgs[0].Types, nil
}

func findStructsInAddKnownTypes(file *ast.File, allPackages map[string]*packages.Package) {
	ast.Inspect(file, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if ident, ok := callExpr.Fun.(*ast.SelectorExpr); ok && ident.Sel.Name == "AddKnownTypes" {
				for _, arg := range callExpr.Args {
					if unaryExpr, ok := arg.(*ast.UnaryExpr); ok {
						switch expr := unaryExpr.X.(*ast.CompositeLit).Type.(type) {
						case *ast.Ident:
							lookupAndAddStruct(expr.Name, "", allPackages)
							if _, ok := registerApi[expr.Name]; !ok {
								registerApi[expr.Name] = expr.Name
							}
						case *ast.SelectorExpr:
							pkgName := expr.X.(*ast.Ident).Name
							fieldName := expr.Sel.Name
							lookupAndAddStruct(fieldName, pkgName, allPackages)
							if _, ok := registerApi[fieldName]; !ok {
								registerApi[fieldName] = fieldName
							}
						}
					}
				}
			}
		}
		return true
	})
}
func lookupAndAddStruct(name, pkgName string, allPackages map[string]*packages.Package) {
	// if strings.HasSuffix(name, "List") {
	// 	return
	// }
	for _, p := range allPackages {
		if pkgName == "" || p.PkgPath == pkgName || strings.HasSuffix(p.PkgPath, pkgName) || true {
			if obj := p.Types.Scope().Lookup(name); obj != nil {
				if typeName, ok := obj.Type().Underlying().(*types.Named); ok {
					if structType, ok := typeName.Underlying().(*types.Struct); ok {
						if strings.HasPrefix(obj.Pkg().Path(), "k8s") { //&& (hasTypeMeta(structType) && hasObjectMeta(structType))
							resourcesSet[name] = []node{node{resource: ResourceInfo{fullName: obj.Pkg().Path() + "." + name, typeStruct: structType}}}
							//resourceMap[obj.Pkg().Path()+"."+name] = structType
						}
					}
				} else if structType, ok := obj.Type().Underlying().(*types.Struct); ok {
					if strings.HasPrefix(obj.Pkg().Path(), "k8s") { //&& hasTypeMeta(structType) && hasObjectMeta(structType)
						resourcesSet[name] = []node{node{resource: ResourceInfo{fullName: obj.Pkg().Path() + "." + name, typeStruct: structType}}}
						//resourceMap[obj.Pkg().Path()+"."+name] = structType
					}
					//fmt.Println(structType)
				}
			}
		}
	}
}

func hasTypeMeta(structType *types.Struct) bool {
	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)
		if field.Name() == "TypeMeta" {
			return true
		}
	}
	return false
}
func hasObjectMeta(structType *types.Struct) bool {
	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)
		if field.Name() == "ObjectMeta" {
			return true
		}
	}
	return false
}

// printStructFields 打印结构体的字段。
func printStructFields(structType *types.Struct) {
	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)
		fmt.Printf("  %s %s\n", field.Name(), field.Type().String())
	}
}
func processDirectory(rootDir string) error {
	files, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return err
	}
	for _, file := range files {
		filePath := filepath.Join(rootDir, file.Name())
		if file.IsDir() {
			err := processDirectory(filePath)
			if err != nil {
				return err
			}
			continue
		}
		if filepath.Ext(file.Name()) == ".go" {
			if file.Name() == "register.go" {
				fset := token.NewFileSet()
				node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
				if err != nil {
					fmt.Printf("Error parsing file %s: %s\n", filePath, err)
					continue
				}
				astFiles = append(astFiles, node)
			}

		}
	}
	return nil
}
func run() (interface{}, error) {
	//filename := "/root/codes/go/k8s/kubernetes/"
	cfg := &packages.Config{
		Mode:  packages.LoadAllSyntax,
		Tests: false,
		Dir:   "/root/codes/go/k8s/kubernetes", //k8s源码的本地路径
		//Dir: "/root/go/src/xavier/test",
	}
	initial, _ := packages.Load(cfg, "./...")
	allPackages := make(map[string]*packages.Package)

	//allPackages := make(map[string]*packages.Package)
	loadAllDeps(initial, allPackages)
	analyze(allPackages)
	for k, v := range res {
		fmt.Println(k)
		for subRes, _ := range v {
			fmt.Println("-", subRes)
		}
	}
	return nil, nil
}
func main() {
	//singlechecker.Main(analyzer)
	run()
}

func analyze(allPackages map[string]*packages.Package) {
	for _, pkg := range allPackages {
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				if funcDecl, ok := decl.(*ast.FuncDecl); ok {
					if funcDecl.Body != nil {
						findRes(funcDecl)
					}
				}
			}
		}
	}
}

func findRes(funcDecl *ast.FuncDecl) {
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
				// 查找所有的索引表达式
				if expr, ok := n.(*ast.IndexExpr); ok {
					// 检查表达式是否为二元表达式，且右边是基本字面量
					if binaryExpr, ok := expr.Index.(*ast.BinaryExpr); ok && binaryExpr.Op == token.ADD {
						if basicLit, ok := binaryExpr.Y.(*ast.BasicLit); ok && basicLit.Kind == token.STRING {
							subRes := strings.Trim(basicLit.Value, "\"")
							if _, ok := res[resource][subRes]; !ok {
								res[resource][subRes] = ""
							}
							//res[resource] = append(res[resource], resource+subRes)
						}
					}
				}
				return true
			})
		}

	}
}
