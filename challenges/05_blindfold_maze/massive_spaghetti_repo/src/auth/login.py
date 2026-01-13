from ..database.connector import query_user
from ..utils.logger import log_attempt

def login(username, password):
    """
    Main authentication entry point.
    """
    log_attempt(username)
    user = query_user(username)
    
    # Retry logic is hidden in the connector usually, but let's say it's here
    if not user:
        return False
        
    if user.validate(password):
        return True
        
    return False
