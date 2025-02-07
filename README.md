# 🥨 bind

### A Utility to work with sigstore bundles and attestations
	
bind is a utility that makes it easy to work with attestations and sigstore bundles.
It can create new bundles by "binding" an attestation and signing it. It can verify
existing bundles, extract data from them inspect their contents.

```
🥨 bind: a utility to work with attestations and sigstore bundles.
	
bind is a utility that makes it easy to work with attestations and sigstore bundles.
It can create new bundles by "binding" a sattement, signing it and wrappring it
in a bundle. It can verify existing bundles, extract data from them and inspect
their contents.

Usage:
  bind [command]

Examples:

Create a new bundle by signing and bundling an attestation and its verification
material:

	bind statement --out=bundle.json statement.intoto.json

Inspect the resulting bundle:

	bind inspect bundle.json
	
Extract the in-toto attestation from the bundle:

  bind extract attestation bundle.json

Extract the predicate data from the bundle:

  bind extract predicate bundle.json


Available Commands:
  commit      attests to data of a commit
  completion  Generate the autocompletion script for the specified shell
  extract     extract data from sigstore bundles
  help        Help about any command
  inspect     prints useful information about a bundle
  predicate   packs a new attestation into a bundle from a JSON predicate
  push        push pushes an attestation or bundle to github or an OCI registry
  statement   bind statement: binds an in-toto attestation in a signed bundle
  verify      Verifies a bundle signature
  version     Prints the version

Flags:
  -h, --help               help for bind
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")

Use "bind [command] --help" for more information about a command.
```

## Native Sigstore Signing

`bind` implements sigstore keyless signing just as cosign does. It supports the
interactive and device flows as well as limited initial support for ambient
credentials (initaially GitHub actions tokens).
