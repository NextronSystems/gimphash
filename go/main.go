package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/goretk/gore"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Printf("Usage: %s executable (executable ...)\n", os.Args[0])
		return
	}

	for _, file := range os.Args[1:] {
		f, err := gore.Open(file)
		if err != nil {
			fmt.Printf("%s: %v\n", file, err)
			continue
		}
		tab, err := f.PCLNTab()
		if err != nil {
			fmt.Printf("%s: %v\n", file, err)
			continue
		}
		var uniquePkgNames = map[string]struct{}{}
		var pkgNames []string

		for _, function := range tab.Funcs {
			pkg := function.Name

			// Do gimphash exclusions, as described in README.md
			if strings.HasPrefix(pkg, "go.") || strings.HasPrefix(pkg, "type.") {
				continue
			}

			if strings.HasPrefix(pkg, "internal/") || strings.HasPrefix(pkg, "vendor/") {
				continue
			}

			pathend := strings.LastIndex(pkg, "/")
			if pathend < 0 {
				pathend = 0
			}

			if i := strings.Index(pkg[pathend:], "."); i != -1 {
				pkg = pkg[:pathend+i]
			} else {
				continue
			}

			firstSeparator := strings.Index(pkg, "/")
			if firstSeparator > 0 {
				urlBase := pkg[:firstSeparator]
				if strings.Index(urlBase, ".") >= 0 {
					switch urlBase {
					case "golang.org", "github.com", "gitlab.com", "gopkg.in", "google.golang.org", "cloud.google.com":
					default:
						continue // Ignore packages from other URLs
					}
				}
			}

			if _, alreadyExists := uniquePkgNames[pkg]; alreadyExists {
				continue
			}
			uniquePkgNames[pkg] = struct{}{}
			pkgNames = append(pkgNames, pkg)
		}
		// Sort and calculated hash
		sort.Strings(pkgNames)
		hash := sha256.New()
		for _, pack := range pkgNames {
			//fmt.Println("Package:", pack)
			hash.Write([]byte(pack))
		}
		fmt.Printf("%s %s\n", hex.EncodeToString(hash.Sum(nil)), file)
	}
}
