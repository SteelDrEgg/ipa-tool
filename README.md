# `ipa-tool`

**A tool for collecting infos of apple ipa**

### Installation
**Over PyPi (recommanded)**
```shell
pip install ipa-tool
```

**Over wheel**
```shell
pip install --user {whl from release}.whl
```

### Use as CLI
**Usage**:

```console
$ ipa-tool [OPTIONS] IPA_PATH
```

**Arguments**:

* `IPA_PATH`: [required]

**Options**:

* `-mi / --get-multi-icon`: [default: False]
* `-o`: Output path
* `--help`: Show this message and exit.

### Use as python package

```python
from ipa_tool import ipaInfos

ipa_tool = ipaInfos(ipa_path)
```
