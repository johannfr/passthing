# passthing

New version of passthing.

## Installation
```bash
pip3 install --user git+https://github.com/johannfr/passthing.git
```

Then add the following two lines to the end of your `.bashrc`:
```bash
export PASSTHING_DB="path/to/store/your/passthing.db"
eval "$(_PASSTHING_COMPLETE=source passthing)"
```
