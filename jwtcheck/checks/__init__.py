"""The ID -> callable registry. Each check exposes run(client) -> Finding."""

from . import sig01

REGISTRY = {
    sig01.CHECK_ID: sig01.run,
}
