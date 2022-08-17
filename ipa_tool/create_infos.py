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

    def __init__(self, ipa_path: str, get_icon: bool = True, get_multi_icon: bool = False):
        from .load_ipa import load_ipa
        from .format_plist import format_plist
        from .get_icon import get_icon, ipng2png
        from .get_size import get_size
        from .analyze_macho import parse_macho, is_encrypted
        from .calc_md5 import calc_md5

        # Calculate md5
        self.md5=calc_md5(ipa_path)

        # Unzip ipa
        ipa = load_ipa(ipa_path)

        # Load plist
        self.rawPlist = format_plist(ipa)

        # Load device family
        try:
            if 1 in self.rawPlist['UIDeviceFamily'] and 2 in self.rawPlist['UIDeviceFamily']:
                self.device = ['iPhone', 'iPad']
            elif 1 in self.rawPlist['UIDeviceFamily']:
                self.device = ['iPhone']
            elif 2 in self.rawPlist['UIDeviceFamily']:
                self.device = ['iPad']
        except Exception:
            self.device = []

        # Load app name
        try:
            self.name = self.rawPlist['CFBundleDisplayName']
        except KeyError:
            try:
                self.name = self.rawPlist['CFBundleName']
            except KeyError:
                try:
                    self.name = self.rawPlist['CFBundleExecutable']
                except Exception:
                    self.name = None

        # Parse macho executable
        macho = parse_macho(self.rawPlist, ipa)
        self.encrypt = is_encrypted(macho)

        # Calc size
        self.size = get_size(ipa)
        self.version = self.rawPlist['CFBundleVersion']
        self.minOS = self.rawPlist['MinimumOSVersion']
        self.bundleID = self.rawPlist['CFBundleIdentifier']

        # Get icon and turns it into png
        if get_icon:
            ipng = get_icon(ipa, self.rawPlist, multi=get_multi_icon)
            self.icon = {}
            if get_multi_icon:
                for icon in ipng.keys():
                    self.icon[icon] = ipng2png(ipng[icon], error=False)
            else:
                name = list(ipng.keys())[0]
                self.icon[name] = ipng2png(ipng[name], error=False)
        else:
            self.icon=None