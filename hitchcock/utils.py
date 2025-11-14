"""Utility functions for Hitchcock."""

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def print_banner() -> None:
    """Print the Hitchcock banner."""
    banner = r""" _     _            _                      _
| |   (_)  _       | |                    | |
| |__  _ _| |_ ____| |__   ____ ___   ___ | |  _
|  _ \| (_   _) ___)  _ \ / ___) _ \ / _ \| |_/ )
| | | | | | |( (___| | | ( (__| |_| | |_| |  _ (
|_| |_|_|  \__)____)_| |_|\____)___/ \___/|_| \_)
"""
    print(banner)
    print("Welcome to Hitchcock - the Wrapto troubleshooting toolkit.")
    print("⚠️  Hitchcock is a testing toolkit. Do not use the generated keys or accounts in production.")


def clear_screen() -> None:
    """Clear the terminal screen."""
    print("\033c", end="")


def section_header(title: str) -> None:
    """Print a section header."""
    print()
    print(f"--- {title} ---")


def section_footer(message: str) -> None:
    """Print a section footer."""
    print()
    print(message)


def error(message: str) -> None:
    """Print an error message in red."""
    print(f"{RED}[error]{RESET} {message}")


def warn(message: str) -> None:
    """Print a warning message in yellow."""
    print(f"{YELLOW}[warn]{RESET} {message}")


def info(message: str) -> None:
    """Print an info message in blue."""
    print(f"{BLUE}[info]{RESET} {message}")


def success(message: str) -> None:
    """Print a success message in green."""
    print(f"{GREEN}[success]{RESET} {message}")


def result(message: str) -> None:
    """Print a result message in cyan."""
    print(f"{CYAN}[result]{RESET} {message}")


def bold(message: str) -> str:
    """Return a bold formatted message."""
    return f"{BOLD}{message}{RESET}"


def bold_yellow(message: str) -> str:
    """Return a bold yellow formatted message."""
    return f"{BOLD}{YELLOW}{message}{RESET}"


def bold_red(message: str) -> str:
    """Return a bold red formatted message."""
    return f"{BOLD}{RED}{message}{RESET}"


def bold_green(message: str) -> str:
    """Return a bold green formatted message."""
    return f"{BOLD}{GREEN}{message}{RESET}"

