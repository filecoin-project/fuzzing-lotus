# Fuzzing tests for Lotus

Received from previous audit for version [v0.3.2](https://github.com/filecoin-project/lotus/releases/tag/v0.3.2), uploaded as is. It hasn't been reviewed in depth.

Note there is an issue with the fuzzers when running go 1.15 so downgrade to go 1.14.
See [here](https://github.com/dvyukov/go-fuzz/issues/294) for details.

## Running the fuzzer

The fuzzers should be run from the `Makefile`. Run `make help` so simple instructions.

To ensure the submodules are correctly initalised and on the correct update run

```bash
make update
```

The fuzzers can be run as follows

```bash
make run-fuzz-XX
```

Where `XX` is the name of the fuzz target. To obtain the name of the fuzz targets
run (or it is the lowercase name of the function in fuzz/*.go e.g. `fuzz.go:FuzzBigInt()` -> `make run-fuzz-bigint`):

```bash
make help
```
