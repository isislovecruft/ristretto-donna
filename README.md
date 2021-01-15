# ristretto-donna

`ristretto-donna` is an implementation of the
[Ristretto group](https://ristretto.group) based on @floodyberry's excellent
[ed25519-donna](https://github.com/floodyberry/ed25519-donna).

## API

See `ristretto-donna.h` for public (and private) API calls.

## Running tests

```sh
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../
make ristretto-donna-test
./ristretto-donna-test
```

## TODOs

* [ ] Expose ristretto basepoint tables and faster and vartime scalar multiplication.
* [ ] Finish `feature/ristretto-from-uniform-bytes` branch.
* [ ] Make wrapper functions for arithmetic operations.
