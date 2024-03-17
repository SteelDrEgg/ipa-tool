import lief, re, zipfile


def parse_macho(plist: dict, ipa_file: zipfile.ZipFile) -> lief.MachO.Binary:
    '''
    :param plist: formatted plist (dict)
    :param ipa_file: zipfile object
    :return: macho object
    '''
    exe_name = plist['CFBundleExecutable']

    name_list = ipa_file.namelist()
    # Use expression to match file
    pt = r'Payload/[^/]*.app/' + exe_name
    pattern = re.compile(pt)
    # Tranversing files in ipa
    for path in name_list:
        path = path.encode("CP437").decode("UTF-8")
        m = pattern.match(path)
        if m is not None:
            exec_path = m.group()
            exec_path = exec_path.encode("UTF-8").decode("CP437")
            break

    # Read executable into memory
    exe = ipa_file.read(exec_path)
    # Use lief to parse executable
    macho = lief.parse(exe)
    # return
    return macho

def is_encrypted(macho: lief.MachO.Binary) -> bool:
    '''
    :param macho: macho object
    :return: bool, is encrypted or not
    '''
    encry_info = macho.get(lief.MachO.LOAD_COMMAND_TYPES.ENCRYPTION_INFO)
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


def find_arch(macho: lief.MachO.Binary) -> str:
    # print(type(macho.header.cpu_type))
    if macho.header.cpu_type == lief.MachO.CPU_TYPES.ARM:
        return "ARM"
    elif macho.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
        return "ARM64"
    else:
        return ""
