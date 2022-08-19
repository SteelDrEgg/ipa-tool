import hashlib
import base64

def calc_md5(path, chunk_size: int=8388608):
    calc = hashlib.md5()
    file=open(path,'rb')
    while True:
        chunk=file.read(chunk_size)
        if chunk:
            calc.update(chunk)
        else:
            break

    return base64.b64encode(calc.digest())