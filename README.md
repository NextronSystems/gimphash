# gimphash

gimphash is a proposed method to calculate an [imphash](https://www.mandiant.com/resources/tracking-malware-import-hashing) equivalent for [Go](https://go.dev/) binaries. It's name stands for **G**o-**imp**ort-**hash**. 

Golang binaries contain their dependencies as part of the executable. These dependencies include both standard library packages and third party dependencies and can be used, analogous to a classical imphash, to identify a Golang project.

The dependencies can be listed using the [pclntab](https://go.dev/src/debug/gosym/pclntab.go) that is part of each Golang binary (also see this [blog post](https://www.mandiant.com/resources/golang-internals-symbol-recovery) by Mandiant). The pclntab contains a number of interesting elements for reverse engineering; for the gimphash we will use the function names that are contained there.

## Calculation

1. Locate the pclntab within a Golang binary
2. Enumerate golang functions using the functab within the pclntab and iterate over their names:
    1. Ignore function names starting with `go.` or `type.` (compile artefacts, runtime internals)
    2. If a function name contains `vendor/`, discard that substring and everything before it
       (e.g. transform `vendor/golang.org/x/text` to `golang.org/x/text`)
    3. Ignore function names containing `internal/`
    4. Find the last `/` in the function name. If no `/` is found, use the start instead. Starting from that position, find the next `.`.
       Discard the `.` and everything after it. (e.g. `golang.org/x/sys/windows.CloseHandle` becomes `golang.org/x/sys/windows`, `main.init` becomes `main`)
       If no `.` is found, ignore the full function name.
    5. If the function name's substring before the first `/` contains a `.` and is NOT in the following list, ignore the function name: (ignoring private repositories; often serve as source code instead of 'imports' that we'd like to hash here)
        - `golang.org`
        - `github.com`
        - `gitlab.com`
        - `gopkg.in`
        - `google.golang.org`
        - `cloud.google.com`
    6. Discard the function name if it was already encountered
    7. Store the resulting name, if it was not ignored so far, in an ordered list
3. Calculate the SHA-256 hash over the concatenated names (no delimiter)

## Proof of Concept Implementations

This repository contains proof-of-concept code in the following languages:

- C
- Go

The [release](https://github.com/NextronSystems/gimphash/releases) section contains prebuilt binaries for Windows and Linux. 

## Feedback

This specification and the related code are a draft. Please use the [Discussions](https://github.com/NextronSystems/gimphash/discussions) section for comments or feedback. 

### Alternative Specifications

#### Step 2 IV

As an alternative to the step 2 iv, we could identify the filepath of the main module and use this to exclude packages that are part of the built project. Feedback on whether this might be better than the current whitelist approach is appreciated.

#### Step 3

We could sort the package names before calculating the hash. However, since the Golang linker seems to generate the pclntab deterministically,
this is apparently not necessary to have a stable hash. Also, since import order can affect the order in the pclntab, the hash is more specific
when not ordered.
