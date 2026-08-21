"""The ID -> callable registry. Each check exposes run(client) -> Finding."""

from . import acl01, acl02, clm01, clm02, clm03, clm04, sec01, sig01, sig02, sig03

REGISTRY = {
    sig01.CHECK_ID: sig01.run,
    sig02.CHECK_ID: sig02.run,
    sig03.CHECK_ID: sig03.run,
    sec01.CHECK_ID: sec01.run,
    clm01.CHECK_ID: clm01.run,
    clm02.CHECK_ID: clm02.run,
    clm03.CHECK_ID: clm03.run,
    clm04.CHECK_ID: clm04.run,
    acl01.CHECK_ID: acl01.run,
    acl02.CHECK_ID: acl02.run,
}
