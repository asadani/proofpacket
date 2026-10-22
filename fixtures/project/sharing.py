def can_reshare(role: str) -> bool:
    """Guests may view a document, but cannot reshare it."""
    return role != "guest"
