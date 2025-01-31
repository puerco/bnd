# bind

## A Utility to Work with Sigstore Bundles
	
bind is a utility that makes it easy to work with attestations and sigstore bundles.
It can create new bundles by "binding" an attestation and signing it. It can verify
existing bundles, extract data from them inspect their contents.

```
Usage:
  bind [command]

Examples:

Create a new bundle by signing and bundling an attestation and its verification
material:

	bind attestation --out=bundle.json att.intoto.json

Inspect the new bundle:
	bind inspect bundle.json
	

Available Commands:
  attestation bind attestation: binds an attestation into a signed bundle
  completion  Generate the autocompletion script for the specified shell
  extract     extract data from sigstore bundles
  help        Help about any command
  inspect     prints useful information about a bundle
  push        push pushes an attestation or bundle to github or an OCI registry
  verify      Verifies a bundle signature
  version     Prints the version

Flags:
  -h, --help               help for bind
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")


```
