class User:
    def __init__(self, name):
        self.name = name
    
    def validate(self, password):
        return True

def query_user(username):
    # Simulated DB connection
    # Complex logic imagined here
    return User(username)
