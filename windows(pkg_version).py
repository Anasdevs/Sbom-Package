import winreg 

def get_installed_software():
    installed_software = []

    reg_keys = [
        winreg.HKEY_LOCAL_MACHINE,
        winreg.HKEY_CURRENT_USER
    ]

    subkeys = [
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]

    for reg_key in reg_keys:
        for subkey in subkeys:
            try:
                with winreg.OpenKey(reg_key, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                    num_subkeys, _, _ = winreg.QueryInfoKey(key)
                    for i in range(num_subkeys):
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                installed_software.append({"Name": display_name, "Version": display_version})
                            except FileNotFoundError:
                                pass
            except FileNotFoundError:
                pass

    return installed_software

# Example usage
installed_software = get_installed_software()
for software in installed_software:
    print(software)
