import zipfile

def load_ipa(path: str):
    # Use zipfile to unzip ipa
    ipa = zipfile.ZipFile(path,'r')
    return ipa