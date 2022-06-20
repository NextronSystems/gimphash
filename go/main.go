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
		var functionNames []string

		for _, function := range tab.Funcs {
			functionName := function.Name

			// Do gimphash exclusions, as described in README.md
			if strings.HasPrefix(functionName, "go.") || strings.HasPrefix(functionName, "type.") {
				continue
			}

			if i := strings.LastIndex(functionName, "vendor/"); i != -1 {
				functionName = functionName[i+len("vendor/"):]
			}

			if strings.Contains(functionName, "internal/") {
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
				if strings.HasPrefix(functionName, blacklisted) {
					isBlacklisted = true
					break
				}
			}
			if isBlacklisted {
				continue
			}

			lastSlash := strings.LastIndex(functionName, "/")
			packageFunctionName := functionName[lastSlash+1:]

			nextDot := strings.Index(packageFunctionName, ".")
			baseFunctionName := packageFunctionName[nextDot+1:]

			if firstAlphanumericCharLowerCase(baseFunctionName) {
				continue
			}

			nextDot = strings.Index(baseFunctionName, ".")
			baseFunctionName = baseFunctionName[nextDot+1:]
			if firstAlphanumericCharLowerCase(baseFunctionName) {
				continue
			}

			functionNames = append(functionNames, functionName)
		}
		// Calculate hash
		hash := sha256.New()
		for _, functionName := range functionNames {
			fmt.Println("Function:", functionName)
			hash.Write([]byte(functionName))
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
