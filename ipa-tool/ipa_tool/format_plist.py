import plistlib, os, re
from typing import Optional

def format_plist(ipa_file):
    '''
    :param ipa_file: zipfile object
    :param progress: progress bar object to update progress bar
    :return: dict: plist
    '''

    def get_plist_path(ipa_file):
        '''
        :param ipa_file: zipfile object
        :return: str: path to ipa
        '''
        # Get all file in ipa
        name_list = ipa_file.namelist()
        # Generate pattern
        # pt = r'Payload' + os.sep + '[^' + os.sep + ']*.app' + os.sep + 'Info.plist'
        pt = r'Payload/[^/]*.app/Info.plist'
        # Use expression to match plist file
        pattern = re.compile(pt)
        # Tranversing files in ipa
        for path in name_list:
            m = pattern.match(path)
            if m is not None:
                return m.group()

    # Find plist path in ipa file
    plist_path = get_plist_path(ipa_file)
    # Read plist in ipa file
    plist_data = ipa_file.read(plist_path)
    # Use plistlib to format plist
    formatted_plist = plistlib.loads(plist_data)
    # return formatted plist
    return formatted_plist

