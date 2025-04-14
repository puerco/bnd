# 🥨 bnd

### A Utility to work with sigstore bundles and attestations
	
bnd is a utility that makes it easy to work with attestations and sigstore bundles.
It can create new bundles by "binding" an attestation and signing it. It can verify
existing bundles, extract data from them inspect their contents.

```
🥨 bnd: a utility to work with attestations and sigstore bundles.
	
bnd (pronounced bind) is a utility that makes it easy to work with attestations
and sigstore bundles. It can create new bundles by "binding" a sattement, signing
it and wrappring it in a bundle. It can verify existing bundles, extract data
from them and inspect their contents.

Usage:
  bnd [command]

Examples:

Create a new bundle by signing and bundling an attestation and its verification
material:

  bnd statement --out=bundle.json statement.intoto.json

Inspect the resulting bundle:

  bnd inspect bundle.json

Extract the in-toto attestation from the bundle:

  bnd extract attestation bundle.json

Extract the predicate data from the bundle:

  bnd extract predicate bundle.json

	

Available Commands:
  commit      attest git commits
  completion  Generate the autocompletion script for the specified shell
  extract     extract data from sigstore bundles
  help        Help about any command
  inspect     prints useful information about a bundle
  pack        packs one or more bundles into a jsonl formatted file
  predicate   packs a new attestation into a bundle from a JSON predicate
  push        pushes an attestation or bundle to a repository
  statement   binds an in-toto attestation in a signed bundle
  unpack      unpacks attestations bundled in a jsonl file
  verify      Verifies a bundle signature
  version     Prints the version

Flags:
  -h, --help               help for bnd
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")

Use "bnd [command] --help" for more information about a command.
```

## Native Sigstore Signing

`bnd` implements sigstore keyless signing just as cosign does. It supports the
interactive and device flows as well as limited initial support for ambient
credentials (initaially GitHub actions tokens).
