# The same recipes under the `properpin` namespace (`just properpin test`), for when there is more than one product.
# A module's recipes run in its own directory, so this points them back at the workspace root.
set working-directory := "../.."

# List the recipes
[private]
default:
    @just --justfile {{ justfile() }} --list properpin

import "properpin.just"
