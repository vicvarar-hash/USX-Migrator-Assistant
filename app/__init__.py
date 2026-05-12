"""Flask application factory."""
import os
import shutil

from flask import Flask


def _ensure_az_on_path() -> None:
    """Add common Azure CLI install locations to PATH if ``az`` is not found.

    Called once at import time so the reloader child process inherits the
    updated PATH.  On Windows, also sets ``AZURE_CLI_PATH`` so that
    ``AzureCliCredential`` can locate ``az.cmd``.
    """
    if shutil.which("az"):
        return

    extra_dirs = []
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    extra_dirs.append(os.path.join(pf, "Microsoft SDKs", "Azure", "CLI2", "wbin"))
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    extra_dirs.append(os.path.join(pf86, "Microsoft SDKs", "Azure", "CLI2", "wbin"))
    extra_dirs.append(os.path.expanduser("~/.local/bin"))

    current = os.environ.get("PATH", "")
    for d in extra_dirs:
        if os.path.isdir(d) and d not in current:
            os.environ["PATH"] = d + os.pathsep + current
            current = os.environ["PATH"]

    # On Windows, AzureCliCredential needs the full path to az.cmd
    if os.name == "nt" and "AZURE_CLI_PATH" not in os.environ:
        for d in extra_dirs:
            az_cmd = os.path.join(d, "az.cmd")
            if os.path.isfile(az_cmd):
                os.environ["AZURE_CLI_PATH"] = az_cmd
                break


# Fix PATH before the reloader forks
_ensure_az_on_path()


def create_app():
    app = Flask(
        __name__,
        static_folder="../static",
        template_folder="templates",
    )
    app.secret_key = "usx-migrator-local-only"

    from .routes import bp
    app.register_blueprint(bp)

    return app
