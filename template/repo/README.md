# @@NAME@@

`@@ID@@`, a ForgeFIRM extension package (runtime `@@RUNTIME@@`).

- `make stage`, `make lint`, `make pack`: the package as it ships, in `build/pkg`.
- `.github/workflows/package.yml`: forgeext's shared workflow tests and packs it on every push, and signs and publishes each new version as a release.
- `key.pub`: the public half of the key that signs it.

How to write, test, sign, publish, and list a package: [Write an extension package](https://docs.forgefirm.org/developers/extensions/).
