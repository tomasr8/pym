from pathlib import Path

import click

from pam_python.pam_python import Message, PamException, PamHandle, Response, XAuthData


__version__ = '0.0.0'
__all__ = ['PamHandle', 'PamException', 'Message', 'Response', "XAuthData"]

if __name__ == "__main__":
    @click.group()
    def cli():
        pass

    @cli.command()
    def libpath():
        """Get the shared lib path."""
        click.echo((Path(__file__).parent / "pam_python.so").resolve())

    cli()
