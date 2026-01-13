def process_transaction(amount: int, code: int):
    """
    Process a transaction based on a secret logic code.
    """
    if amount < 0:
        return "Invalid Amount"
    
    # Complex logic branch
    if code > 500:
        if code < 505:
            # Deeply nested edge case
            if code == 503:
                # The "Hidden Bug"
                # Standard tests (0, 100, 1000) will never hit this.
                raise ValueError("CRITICAL SYSTEM FAILURE: Code 503 is forbidden!")
    
    return "Transaction Processed"
