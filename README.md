gimphash
--------

gimphash is a proposed method to calculate an imphash equivalent for Golang binaries.

Golang binaries contain their dependencies as part of the executable. These dependencies include both standard library packages and third party dependencies and can be used, analogous to a classical imphash, to identify a Golang project.

The dependencies can be listed using the pclntab that is part of each Golang binary. The pclntab contains a number of interesting elements for reverse engineering; for the gimphash we will use the function names that are contained there.

Calculation
-----------
1. Locate the pclntab within a Golang binary
2. Enumerate golang functions using the functab within the pclntab:
    1. Ignore functions starting with go. or type.
    2. Ignore functions starting with internal/ or vendor/
    3. Reduce the function name to the part before the first . that is after the last / (e.g. golang.org/x/sys/windows.CloseHandle becomes golang.org/x/sys/windows)
    4. If the part before the first / contains a . and is not in the following list, ignore the function name:
        - golang.org
        - github.com
        - gitlab.com
        - gopkg.in
        - google.golang.org
        - cloud.google.com
3. Sort the resulting package names
4. Calculate the SHA-256 hash over the concatenated names

Feedback
--------

Alternative to the step 2 iv: identify the filepath of the main module and use this to exclude packages that are part of the built project. 

Feedback on whether this might be better than the current whitelist approach is appreciated.
