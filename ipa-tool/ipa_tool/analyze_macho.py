import lief, os, re

def parse_macho(plist, ipa_file):
    '''
    :param plist: formatted plist (dict)
    :param ipa_file: zipfile object
    :return: macho object
    '''
    exe_name=plist['CFBundleExecutable']

    name_list = ipa_file.namelist()
    # Use expression to match file
    pt = r'Payload/[^/]*.app/' + exe_name
    pattern = re.compile(pt)
    # Tranversing files in ipa
    for path in name_list:
        m = pattern.match(path)
        if m is not None:
            exec_path=m.group()
            break

    # Read executable into memory
    exec=ipa_file.read(exec_path)
    # Use lief to parse executable
    macho = lief.parse(exec)
    # return
    return macho

def is_encrypted(macho):
    '''
    :param macho: macho object
    :return: bool, is encrypted or not
    '''
    encry_info=macho.get(lief.MachO.LOAD_COMMAND_TYPES.ENCRYPTION_INFO)
    if encry_info:
        if encry_info.crypt_id == 1:
            return True
        else:
            return False
    else:
        encry_info = macho.get(lief.MachO.LOAD_COMMAND_TYPES.ENCRYPTION_INFO_64)
        if encry_info:
            if encry_info.crypt_id == 1:
                return True
        return False