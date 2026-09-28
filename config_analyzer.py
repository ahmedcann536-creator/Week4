import os
import subprocess


def check_firewall():
    try:
        result = subprocess.run(
            ["ufw", "status"],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout.strip()

        if "Status: active" in output:
            return "PASS", "UFW firewall is active."
        elif "Status: inactive" in output:
            return "WARNING", "UFW firewall is inactive."
        else:
            return "INFO", "UFW status could not be determined."

    except FileNotFoundError:
        return "INFO", "UFW is not installed."
    except Exception as error:
        return "INFO", f"Firewall check error: {error}"


def check_ssh_config():
    path = "/etc/ssh/sshd_config"

    if not os.path.exists(path):
        return "INFO", "SSH server configuration was not found."

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        root_login = None
        password_auth = None

        for line in lines:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) >= 2:
                setting = parts[0].lower()
                value = parts[1].lower()

                if setting == "permitrootlogin":
                    root_login = value

                elif setting == "passwordauthentication":
                    password_auth = value

        if root_login == "no":
            root_result = "PASS"
            root_message = "SSH root login is disabled."
        else:
            root_result = "WARNING"
            root_message = "SSH root login may be enabled."

        if password_auth == "no":
            password_result = "PASS"
            password_message = "SSH password authentication is disabled."
        else:
            password_result = "WARNING"
            password_message = "SSH password authentication may be enabled."

        return (
            "PASS" if root_result == "PASS" and password_result == "PASS" else "WARNING",
            f"{root_message} {password_message}"
        )

    except PermissionError:
        return "WARNING", "Permission denied while reading SSH configuration."
    except Exception as error:
        return "INFO", f"SSH configuration check error: {error}"


def check_file_permissions():
    files_to_check = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config"
    ]

    warnings = []

    for path in files_to_check:
        if not os.path.exists(path):
            continue

        try:
            mode = oct(os.stat(path).st_mode & 0o777)

            if path == "/etc/shadow" and mode != "0o640" and mode != "0o600":
                warnings.append(f"{path} permissions are {mode}")

            elif path != "/etc/shadow" and mode not in ["0o644", "0o640", "0o600"]:
                warnings.append(f"{path} permissions are {mode}")

        except PermissionError:
            warnings.append(f"Permission denied checking {path}")

    if warnings:
        return "WARNING", "; ".join(warnings)

    return "PASS", "Important configuration file permissions look reasonable."


def main():
    print("=" * 60)
    print("        WEEK 4 - CONFIGURATION SECURITY ANALYZER")
    print("=" * 60)

    checks = [
        ("Firewall", check_firewall),
        ("SSH Configuration", check_ssh_config),
        ("File Permissions", check_file_permissions)
    ]

    for name, check in checks:
        status, message = check()
        print(f"\n[{status}] {name}")
        print(f"    {message}")

    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
