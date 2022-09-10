# `ipa-tool`

**A tool for collecting infos of apple ipa**

### Installation
**Over PyPi (recommanded)**
```shell
pip install ipa-tool
```

**Over wheel**
```shell
pip install --user {find in release}.whl
```

### Use as CLI
**Usage**:

```console
$ ipa-tool COMMAND [Options] [ARGS]... 
```

**Command**:

* `get-info`: Returns ipa infos in json
* `cgbi2png`: Turns apple cgbi into normal png

**Arguments**:

* `IPA_PATH`: [required]

**Options**:

* `-mi / --get-multi-icon`: [default: False]
* `-o`: Output path
* `--help`: Show this message and exit.

### Use as python package

```python
from ipa_tool import ipaInfos

ipa_infos = ipaInfos( {ipa_path} )
```

`ipaInfos` will return a class
```python
class ipaInfos():
    name: str
    device: list
    size: int
    version: str
    bundleID: str
    encrypt: bool
    minOS: str
    icon: dict
    md5: bytes
    rawPlist: dict
```
You can turn it into dict by
```python
ipa_info_dict = ipa_tool.__dict__
```
