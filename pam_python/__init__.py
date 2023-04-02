from pathlib import Path

import click

from pam_python.pam_python import Message, PamException, PamHandle, Response, XAuthData


__version__ = '0.0.0'
__all__ = ['PamHandle', 'PamException', 'Message', 'Response', "XAuthData"]


def _get_lib_path():
    return (Path(__file__).parent / "pam_python.so").resolve()

if __name__ == "__main__":
    @click.group()
    def cli():
        pass

    @cli.command()
    def libpath():
        """Get the shared lib path."""
        click.echo(_get_lib_path())

    @cli.command("print-config")
    @click.argument("filename", type=click.Path(exists=True), help="Path to the Python PAM file")
    def config(filename):
        """Create and print a dummy PAM config file."""
        lib_path = _get_lib_path()
        file_path = Path(filename).resolve()
        click.echo(f"account\trequired\t{lib_path} {file_path}")
        click.echo(f"auth\trequired\t{lib_path} {file_path}")
        click.echo(f"session\trequired\t{lib_path} {file_path}")
        click.echo(f"password\trequired\t{lib_path} {file_path}")

    cli()
