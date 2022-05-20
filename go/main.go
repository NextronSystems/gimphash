package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode"

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
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			continue
		}
		tab, err := f.PCLNTab()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			continue
		}
		var pkgNames []string

		for _, function := range tab.Funcs {
			pkg := function.Name

			// Do gimphash exclusions, as described in README.md
			if strings.HasPrefix(pkg, "go.") || strings.HasPrefix(pkg, "type.") {
				continue
			}

			if i := strings.LastIndex(pkg, "vendor/"); i != -1 {
				pkg = pkg[i:]
			}

			if strings.Contains(pkg, "internal/") {
				continue
			}

			var isBlacklisted bool
			for _, blacklisted := range []string{
				"runtime",
				"sync",
				"syscall",
				"type",
				"time",
				"unicode",
				"reflect",
				"strconv",
			} {
				if strings.HasPrefix(pkg, blacklisted) {
					isBlacklisted = true
					break
				}
			}
			if isBlacklisted {
				continue
			}

			lastSlash := strings.LastIndex(pkg, "/")
			packageFunctionName := pkg[lastSlash+1:]

			nextDot := strings.Index(packageFunctionName, ".")
			functionName := packageFunctionName[nextDot+1:]

			if firstAlphanumericCharLowerCase(functionName) {
				continue
			}

			nextDot = strings.Index(functionName, ".")
			functionName = functionName[nextDot+1:]
			if firstAlphanumericCharLowerCase(functionName) {
				continue
			}

			pkgNames = append(pkgNames, pkg)
		}
		// Calculate hash
		hash := sha256.New()
		for _, pack := range pkgNames {
			//fmt.Println("Package:", pack)
			hash.Write([]byte(pack))
		}
		fmt.Printf("%s %s\n", hex.EncodeToString(hash.Sum(nil)), file)
	}
}

func firstAlphanumericCharLowerCase(s string) bool {
	for _, c := range s {
		if unicode.IsLower(c) {
			return true
		}
		if unicode.IsUpper(c) || unicode.IsNumber(c) {
			return false
		}
	}
	return false
}
