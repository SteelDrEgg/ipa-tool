import os, re

def get_icon(ipa, plist):
    '''
    :param ipa: zipfile object
    :param plist: dict, formatted plist
    :return: icon read
    '''
    icon_name = ''
    # I hate people who doesn't follow developer's guide
    try:
        icon_name = plist['CFBundleIconFile']
    except Exception:
        try:
            icon_name = plist['CFBundleIconFiles']
        except Exception:
            try:
                icon_name = plist['CFBundleIcons']['CFBundlePrimaryIcon']['CFBundleIconFiles']
            except Exception:
                try:
                    icon_name = plist['CFBundlePrimaryIcon']['CFBundleIconFiles']
                except Exception:
                    return fuzzy_search(ipa)

    # Turning adding .png to ipa
    if isinstance(icon_name, str):
        icon_name = [icon_name]

    icons={}
    for file in ipa.namelist():
        for name in icon_name:
            if name in file.split(os.sep)[-1]:
                icons[file.split(os.sep)[-1]]=ipa.read(file)
    if len(icons)>0:
        return icons
    else:
        return fuzzy_search(ipa)


def fuzzy_search(ipa):
    # If can't fount icon
    imgs = []
    # Grab all png files
    pt = r'Payload' + os.sep + '[^' + os.sep + ']*.app' + os.sep + '*.png'
    pattern = re.compile(pt)
    # Tranversing files in ipa
    for file in ipa.namelist():
        matched = pattern.match(file)
        if matched is not None:
            imgs.append(matched.group(0))

    # Depend whether img is icon
    candidates = []
    for img in imgs:
        if ('icon' in img) or ('Icon' in img):
            candidates.append(img)
    # Is icon really app icon? It could be social media icon
    for icon in candidates:
        if ('@' in icon) or ('x' in icon):
            icon_name = icon
            break

    try:
        # Returning
        return ipa.read(icon_name)
    except UnboundLocalError:
        return None


def ipng2png(ipng: bytes, error: bool = True) -> bytes:
    '''
    :param ipng: bytes: apple png
    :param error: bool: raise error if not CgBI
    :return: bytes: image;
    '''
    ipng2png.__doc__ = "This is for turning apple cgbi png to standard png"
    import zlib
    # 8 byte signature header which allows computer to know that it's a png
    signature_header = ipng[:8]
    # Everything other than signature header
    rest_of_png = ipng[8::]

    # Create a new png starting with the signature header (https://www.w3.org/TR/PNG-Rationale.html#R.PNG-file-signature)
    new_PNG = signature_header
    # The index of byte reading
    current_byte = 8

    # Have CgBI?
    cgbi=False

    # Going through every chunk in png
    while current_byte < len(ipng):
        # Chunk layout https://www.w3.org/TR/PNG-Structure.html#Chunk-layout
        # Length: 4 bytes
        # Chunk Type: 4 bytes ASCII letters
        # Chunk Data: defined in 'Length' field
        # CRC: 4 bytes

        # Reading length field (chunk length is the length of data, not the whole chunk)
        chunk_length_raw = ipng[current_byte:current_byte + 4]
        # Turning bytes into integer
        chunk_length = int.from_bytes(chunk_length_raw, 'big')
        current_byte = current_byte + 4
        # Reading type field
        chunk_type_raw = ipng[current_byte:current_byte + 4]
        # Turning bytes into string
        chunk_type = str(chunk_type_raw, encoding='ASCII')
        current_byte = current_byte + 4
        # Extracting chunk_data
        chunk_data = ipng[current_byte:current_byte + chunk_length]
        # Reading CRC field
        chunk_CRC = ipng[current_byte + chunk_length:current_byte + chunk_length + 4]

        # Removing CgBI chunk
        if chunk_type == 'CgBI':
            current_byte = current_byte + chunk_length + 4
            cgbi=True
            continue
        # Reading img width and height
        elif chunk_type == 'IHDR':
            if cgbi:
                img_width = int.from_bytes(chunk_data[0:4], 'big')
                img_height = int.from_bytes(chunk_data[4:8], 'big')
            else:
                if error:
                    raise ValueError("CgBI chunk not found, mey be a normal PNG!")
                    raise
                else:
                    return ipng
        # Turning BGRA into RGBA
        elif chunk_type == 'IDAT':
            # Decompressing, see more https://iphonedev.wiki/index.php/CgBI_file_format#Differences_from_PNG
            try:
                buffer_size = img_width * img_height * 4 + img_height
                chunk_data = zlib.decompress(chunk_data, wbits=-8, bufsize=buffer_size)
            except Exception:
                if error:
                    raise ArithmeticError('Error resolving IDAT chunk!')
                else:
                    pass

            # Creating bytes like new data
            new_data = b''
            for y in range(img_height):
                # index of current position
                position = len(new_data)
                # Separator
                new_data = new_data + bytes([chunk_data[position]])
                for x in range(img_width):
                    # index of current pixes
                    pixel = len(new_data)
                    # Red
                    new_data = new_data + bytes([chunk_data[pixel + 2]])
                    # Green
                    new_data = new_data + bytes([chunk_data[pixel + 1]])
                    # Blue
                    new_data = new_data + bytes([chunk_data[pixel + 0]])
                    # Alpha
                    new_data = new_data + bytes([chunk_data[pixel + 3]])
            #
            chunk_data = new_data
            chunk_data = zlib.compress(chunk_data)
            chunk_length_raw = len(chunk_data).to_bytes(4, 'big')

        new_CRC = zlib.crc32(chunk_type_raw)
        new_CRC = zlib.crc32(chunk_data, new_CRC)
        new_CRC = (new_CRC + 0x100000000) % 0x100000000
        new_PNG = new_PNG + chunk_length_raw + chunk_type_raw + chunk_data + new_CRC.to_bytes(4, 'big')

        # If it's the end, stop immedietly
        if chunk_type == 'IEND':
            break

        current_byte = current_byte + chunk_length + 4

    return new_PNG
