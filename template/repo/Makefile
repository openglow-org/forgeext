# @@NAME@@ (@@ID@@). `make stage` lays out in build/pkg what the package
# ships: the manifest, and those of ui, bin, lib, and share that exist, and
# nothing of the repository's own files. `make lint` judges it as the
# machine does, and `make pack` packs it (KEY=<file.priv> signs it; its .pub
# must be beside it). FFX is forgeext's tools/ffx: a sibling checkout by
# default, and the kit's in the shared workflow.

FFX  ?= ../forgeext/tools/ffx
SHIP  = manifest.json $(wildcard ui bin lib share)
@@BUILD@@
stage: manifest.json@@STAGE_NEEDS@@
	rm -rf build/pkg
	mkdir -p build/pkg
	cp -R $(SHIP) build/pkg/

lint: stage
	python3 $(FFX) lint build/pkg

pack: stage
	python3 $(FFX) pack build/pkg $(if $(KEY),--key $(KEY)) --out build/@@ID@@.ffx

clean:
	rm -rf build@@CLEAN@@

.PHONY: stage lint pack clean
