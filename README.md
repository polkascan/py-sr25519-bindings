# py-sr25519-bindings
Python bindings for sr25519 library: https://github.com/w3f/schnorrkel

Reference to https://github.com/LocalCoinSwap/kusama-reference-implementation/tree/improve-trading-tests/bindings and https://gitlab.com/kauriid/schnorrpy/ for the initial work 

## Installation

### Install from PyPI

```
pip install py-sr25519-bindings
```

### Compile for local development

```
pip install -r requirements.txt
maturin develop
```
### Build wheelhouses
```
pip install -r requirements.txt

# Build local OS wheelhouse
maturin build

# Build manylinux1 wheelhouse
docker build . --tag polkasource/maturin
docker run --rm -i -v $(pwd):/io polkasource/maturin build

```

## License
https://github.com/polkascan/py-sr25519-bindings/blob/master/LICENSE
