# CSO Proxy

This application is designed as a proxy to trick
the [Container Security Operator](https://github.com/quay/container-security-operator) into scanning non-Quay
registries. It does this by implementing the `.well-known/app-capabilities` API that Quay does.
