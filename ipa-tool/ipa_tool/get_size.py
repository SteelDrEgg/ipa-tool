def get_size(ipa):
    '''
    :param ipa: zipfile object
    :return: int, bytes
    '''
    files=ipa.infolist()
    size=0
    for info in files:
        size=size+info.file_size
    return size