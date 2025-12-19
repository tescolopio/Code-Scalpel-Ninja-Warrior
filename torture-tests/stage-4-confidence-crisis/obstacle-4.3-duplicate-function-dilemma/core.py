class BaseHandler:
    def validate(self, payload: dict) -> bool:
        # Base expectation: require a type field.
        return "type" in payload


class Handler(BaseHandler):
    def validate(self, payload: dict) -> bool:  # overrides BaseHandler.validate
        # Overrides with stricter rules, but assumes payload is already sanitized.
        return super().validate(payload) and payload.get("type") in {"user", "admin"}
