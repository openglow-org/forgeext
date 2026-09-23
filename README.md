# forgeext

The extension host for
[ForgeFIRM](https://github.com/openglow-org/forgefirm)-powered Glowforge
lasers.

It verifies an extension archive (`.ffx`: an fwup archive with the product
`ForgeFIRM extension`, one resource, and no task), unpacks it under
`/data/forgefirm/ext`, and keeps the record of what is installed, who signed
it, and what the operator granted it. It is a separate process from
[forgectrl](https://github.com/openglow-org/forgectrl), which stays the
machine's one front door.

## Documentation

Everything is on **<https://docs.forgefirm.org/>**, which is the source of
truth for this project. This README is an index card.

| Subject | Page |
|---|---|
| Extension packages: the archive, what the verifier takes, the trust tiers, the manifest, the capabilities, what is installed, the command line | [Extension packages](https://docs.forgefirm.org/technical/forgefirm/extensions/) |
| The extension sandbox the image holds ready: the account pool, the cgroup tree, the deny rules | [Image and BSP](https://docs.forgefirm.org/technical/forgefirm/image-and-bsp/#the-extension-sandbox) |
| A package's own page and the panel's bridge; the bridge client every page pastes in is `sdk/js/ffx-bridge.js` | [A package's own page](https://docs.forgefirm.org/technical/forgefirm/extensions/#a-packages-own-page) |
| The official packages, under `packages/`: visual alignment | [Visual alignment](https://docs.forgefirm.org/usage/alignment/) |
| How to build and test | [`AGENTS.md`](AGENTS.md) |

## License

MIT. See [`LICENSE`](LICENSE).
