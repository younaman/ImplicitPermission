package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"
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
	allPackages  []*packages.Package
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
	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))

	ssaPkgs := make(map[*packages.Package]*ssa.Package)
	for _, pkg := range visited {
		ssaPkg := prog.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, false)
		ssaPkgs[pkg] = ssaPkg
	}

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
		allPackages = append(allPackages, pkg)
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
	//rootDir := "D:\\Code\\Go\\src\\k8s\\kubernetes\\staging\\src\\k8s.io"
	//filename := "/root/codes/go/k8s/kubernetes/"
	err = loadPackagesRecursive(rootDir)
	if err != nil {
		fmt.Println(err)
	}
	analyze()
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

func analyze() {
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
				if expr, ok := n.(*ast.IndexExpr); ok {
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
