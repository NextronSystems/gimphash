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
    4. Ignore function names that start with one of the following standard library packages:
        - `runtime`
        - `sync`
        - `syscall`
        - `type`
        - `time`
        - `unicode`
        - `reflect`
        - `strconv`
    5. Ignore function names that are not public or where their receivers are not public. In order to do so:
       1. Find the last `/` in the function name. If no `/` is found, use the start instead. Starting from that position, find the next `.`.
       2. Extract the *base function name* as everything after that `.`. If no `.` was found, use everything after the `/` index calculated in the previous step.
       3. Ignore the function if the first alphanumeric character in the base function name is a lower case character.
       4. If another `.` exists within the base function name, ignore the function if the first alphanumeric character after that `.` is a lower case character.
    6. Store the resulting name, if it was not ignored so far, in an ordered list
3. Calculate the SHA-256 hash over the concatenated names (no delimiter)

## Proof of Concept Implementations

This repository contains proof-of-concept code in the following languages:

- C
- Go

The [release](https://github.com/NextronSystems/gimphash/releases) section contains prebuilt binaries for Windows and Linux. 

### Usage Examples

Run the Gimphash calculator on a single file
```bash
./c_gimphash_linux /mnt/malware-repo/Godoh/godoh-windows64.exe
8200e76e42c4e9cf2bb308d76c017cbdcde5cbbf95e99e02b14d05e7b21505f3 /mnt/mal/Godoh/godoh-windows64.exe
```

Run the Gimphash calculator on a malware repository
```bash
find /mnt/malware-repo/ -type f -exec ./go_gimphash_linux {} \; 2>/dev/null
...
```

### Clustering Example

![Screenshot 2022-07-02 at 10 11 38](https://user-images.githubusercontent.com/2851492/176993921-e25e7106-a798-4031-9016-90a097c7e77f.png)

