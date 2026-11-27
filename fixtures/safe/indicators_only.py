"""Inert feature fixture. No theft, browser access or network operations."""
DOCUMENTATION_URL = "https://fixture.invalid/documentation"
DOCUMENTATION_FIELD = "Login Data is a documentation marker."
def describe():
    return DOCUMENTATION_URL, DOCUMENTATION_FIELD
