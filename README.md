gimphash
--------

gimphash is a proposed method to calculate an imphash equivalent for Golang binaries.

Golang binaries contain their dependencies as part of the executable. These dependencies include both standard library packages and third party dependencies and can be used, analogous to a classical imphash, to identify a Golang project.

The dependencies can be listed using the pclntab that is part of each Golang binary. The pclntab contains a number of interesting elements for reverse engineering; for the gimphash we will use the function names that are contained there.

Calculation
-----------
- Locate the pclntab within a Golang binary
- Enumerate golang functions using the functab within the pclntab:
  - Ignore functions starting with go. or type.
  - Ignore functions starting with internal/ or vendor/
  - Reduce the function name to the part before the first . that is after the last / (e.g. golang.org/x/sys/windows.CloseHandle becomes golang.org/x/sys/windows)
  - If the part before the first / contains a . and is not in the following list, ignore the function name:
    - golang.org
    - github.com
    - gitlab.com
    - gopkg.in
    - google.golang.org
    - cloud.google.com
  - (Alternative to last step: identify the filepath of the main module and use this to exclude packages that are part of the built project. Feedback on whether this might be better than the current whitelist approach is appreciated.)
- Sort the resulting package names
- Calculate the SHA-256 hash over the concatenated names
