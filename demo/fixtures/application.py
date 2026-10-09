"""Call-site evidence supplied to the exploitability model; not executed by intake."""
from slug_dependency import normalize_slug

def package_route(user_supplied_slug):
    return '/packages/' + normalize_slug(user_supplied_slug)
