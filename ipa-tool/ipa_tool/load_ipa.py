import zipfile

def load_ipa(path: str) -> zipfile.ZipFile:
    # Use zipfile to unzip ipa
    ipa = zipfile.ZipFile(path,'r')
    return ipa