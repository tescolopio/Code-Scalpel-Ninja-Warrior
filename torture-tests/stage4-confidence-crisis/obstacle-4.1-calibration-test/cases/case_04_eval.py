def unsafe_eval(user_code: str, context: dict):
    # Vulnerable: executes attacker-controlled code
    return eval(user_code, {}, context)
