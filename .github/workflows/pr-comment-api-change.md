This PR changes files in the API project. Does it change _any_ of the API interfaces in _any way_? Please note that this includes the following types of changes:
- Changing the signature of an existing interface method
- Adding a new method to an existing interface
- Adding a required data member to a class that an existing interface method consumes

Because any of these changes can potentially break a downstream consumer with customized interface implementations, these changes need to be treated as breaking changes. Please do one of the following:

## Option 1 - Publish this as a breaking change
1. Update the documentation to show the new functionality
2. Bump the major version in the next release
3. Be sure to highlight of the breaking changes in the release notes

## Option 2 - Refactor the changes to be non-breaking
1. Review [this commit](https://github.com/microsoft/sbom-tool/commit/4d0ce83e194ed6feace53666aeb6280f5b8b8769), which adds a new interface in a backward-compatible way
2. Refactor the change to follow this pattern so that existing interfaces are left completely intact
3. Bump the minor version in the next release
