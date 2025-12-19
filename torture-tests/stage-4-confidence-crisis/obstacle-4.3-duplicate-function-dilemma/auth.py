def validate(token: str) -> bool:
    # Minimal structural check only; does not verify signature.
    return bool(token and token.count(".") == 2)
