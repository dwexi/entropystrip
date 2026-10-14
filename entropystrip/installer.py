r"""
Installer utility for registering EntropyStrip globally on Windows.
Copies standalone executable to %LOCALAPPDATA%\Programs\EntropyStrip
and registers that path in the User Environment PATH via registry.
"""

import os
import sys
import shutil
import ctypes
import subprocess
from ctypes import wintypes
from typing import Tuple, Optional

try:
    import winreg
except ImportError:
    winreg = None

try:
    from .reporters.console import console
except (ImportError, ValueError):
    from entropystrip.reporters.console import console


def get_install_paths() -> Tuple[str, str]:
    """Returns (install_dir, install_exe_path)."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        local_app_data = os.path.expanduser(r"~\AppData\Local")
    install_dir = os.path.join(local_app_data, "Programs", "EntropyStrip")
    install_exe = os.path.join(install_dir, "entropystrip.exe")
    return install_dir, install_exe


def is_in_user_path(target_dir: str) -> bool:
    """Checks if target_dir is registered in the HKCU\\Environment\\Path registry value."""
    if sys.platform != "win32" or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
            raw_path, _ = winreg.QueryValueEx(key, "Path")
            entries = [os.path.normcase(os.path.normpath(p.strip())) for p in raw_path.split(";") if p.strip()]
            norm_target = os.path.normcase(os.path.normpath(target_dir))
            return norm_target in entries
    except Exception:
        return False


def check_existing_install() -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Checks if EntropyStrip is already available globally in PATH.
    Returns:
        (is_installed: bool, install_type: 'standalone' | 'python' | None, path: Optional[str])
    """
    install_dir, install_exe = get_install_paths()
    if os.path.isfile(install_exe) and is_in_user_path(install_dir):
        return True, "standalone", install_exe

    existing = shutil.which("entropystrip") or shutil.which("entropystrip.exe")
    if existing:
        curr_exe = getattr(sys, "executable", "")
        # Ignore if found executable is simply the currently running binary in current working directory
        if os.path.normcase(os.path.abspath(existing)) != os.path.normcase(os.path.abspath(curr_exe)):
            return True, "python", existing

    return False, None, None


def is_installed_globally() -> bool:
    """Returns True if EntropyStrip is available globally in Windows PATH (standalone or via Python)."""
    installed, _, _ = check_existing_install()
    return installed


def broadcast_environment_change() -> None:
    """Broadcasts WM_SETTINGCHANGE to notify Windows Explorer and shells of updated PATH."""
    if sys.platform != "win32":
        return
    try:
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        result = wintypes.DWORD()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            "Environment",
            SMTO_ABORTIFHUNG,
            5000,
            ctypes.byref(result),
        )
    except Exception:
        pass


def install_globally(quiet: bool = False) -> bool:
    """
    Installs EntropyStrip into %LOCALAPPDATA%\\Programs\\EntropyStrip
    and adds that directory to the User PATH.
    """
    if sys.platform != "win32":
        if not quiet:
            console.print("[yellow]Global installer is currently implemented for Windows.[/yellow]")
        return False

    install_dir, install_exe = get_install_paths()

    # Determine source executable
    src_exe: Optional[str] = None
    if getattr(sys, "frozen", False):
        src_exe = sys.executable
    else:
        possible_exes = [
            os.path.join(os.getcwd(), "dist", "entropystrip.exe"),
            shutil.which("entropystrip.exe"),
            shutil.which("entropystrip"),
        ]
        for p in possible_exes:
            if p and os.path.isfile(p):
                src_exe = p
                break

    try:
        os.makedirs(install_dir, exist_ok=True)
        if src_exe and os.path.abspath(src_exe).lower() != os.path.abspath(install_exe).lower():
            shutil.copy2(src_exe, install_exe)
    except Exception as e:
        if not quiet:
            console.print(f"[red]Error copying executable: {e}[/red]")
        return False

    # Add to User PATH if not present
    path_added = False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                raw_path, reg_type = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                raw_path, reg_type = "", winreg.REG_EXPAND_SZ

            entries = [p.strip() for p in raw_path.split(";") if p.strip()]
            norm_entries = [os.path.normcase(os.path.normpath(p)) for p in entries]
            norm_install = os.path.normcase(os.path.normpath(install_dir))

            if norm_install not in norm_entries:
                entries.append(install_dir)
                new_path = ";".join(entries)
                winreg.SetValueEx(key, "Path", 0, reg_type, new_path)
                path_added = True

        if path_added:
            broadcast_environment_change()
            os.environ["PATH"] = install_dir + os.pathsep + os.environ.get("PATH", "")

        if not quiet:
            console.print("[bold green][✓] EntropyStrip is installed globally![/bold green]")
            console.print(f"  * Binary location: [cyan]{install_exe}[/cyan]")
            if path_added:
                console.print(f"  * Added to User PATH: [cyan]{install_dir}[/cyan]")
            console.print("  * You can now run [yellow]entropystrip[/yellow] in any Command Prompt or PowerShell window.\n")
        return True

    except Exception as e:
        if not quiet:
            console.print(f"[red]Error registering PATH in registry: {e}[/red]")
        return False


def uninstall_globally(quiet: bool = False, prompt_python: bool = True) -> bool:
    """Removes EntropyStrip from User PATH and optionally from Python environment."""
    if sys.platform != "win32":
        return False

    install_dir, install_exe = get_install_paths()
    removed_standalone = False

    # 1. Clean registry and delete standalone installation
    if winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    raw_path, reg_type = winreg.QueryValueEx(key, "Path")
                    entries = [p.strip() for p in raw_path.split(";") if p.strip()]
                    norm_install = os.path.normcase(os.path.normpath(install_dir))
                    new_entries = [p for p in entries if os.path.normcase(os.path.normpath(p)) != norm_install]
                    if len(new_entries) != len(entries):
                        winreg.SetValueEx(key, "Path", 0, reg_type, ";".join(new_entries))
                        removed_standalone = True
                except FileNotFoundError:
                    pass

            if removed_standalone:
                broadcast_environment_change()

            if os.path.isdir(install_dir):
                try:
                    shutil.rmtree(install_dir)
                    removed_standalone = True
                except Exception:
                    pass
        except Exception as e:
            if not quiet:
                console.print(f"[red]Error removing standalone installation: {e}[/red]")

    if removed_standalone and not quiet:
        console.print("[green][✓] Standalone EntropyStrip successfully removed from Windows PATH.[/green]")

    # 2. Check if installed in Python via pip
    pip_found = False
    try:
        pip_exe = shutil.which("pip") or shutil.which("pip3")
        if pip_exe:
            check = subprocess.run([pip_exe, "show", "entropystrip"], capture_output=True, text=True)
            if check.returncode == 0:
                pip_found = True
                if prompt_python and sys.stdin and sys.stdin.isatty():
                    try:
                        ans = input("\nEntropyStrip is also installed in your Python environment via pip.\nDo you want to uninstall it from Python too? [y/N]: ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        ans = "n"
                    if ans in ("y", "yes"):
                        res = subprocess.run([pip_exe, "uninstall", "-y", "entropystrip"], capture_output=True, text=True)
                        if res.returncode == 0:
                            if not quiet:
                                console.print("[green][✓] Successfully uninstalled from Python environment.[/green]")
                        else:
                            if not quiet:
                                console.print(f"[red]Error uninstalling from pip: {res.stderr}[/red]")
                    else:
                        if not quiet:
                            console.print("[dim]Python package retained.[/dim]")
                else:
                    if not quiet:
                        console.print("[dim]Note: EntropyStrip is also installed in Python. Run 'pip uninstall entropystrip' to remove it from Python.[/dim]")
    except Exception:
        pass

    if not removed_standalone and not pip_found and not quiet:
        console.print("[dim]EntropyStrip was not found in Windows PATH or Python environment.[/dim]")

    return True
