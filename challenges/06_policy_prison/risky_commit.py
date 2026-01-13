import hashlib # Banned?
import os

def quick_fix(data):
    # No docstring
    # High complexity if I add loops/branches
    if data:
        for i in range(10):
            if i % 2 == 0:
                print("Even")
            else:
                # VIOLATION: Weak crypto
                h = hashlib.md5(data.encode()).hexdigest() 
                # VIOLATION: Command injection risk
                os.system(f"echo {h}") 
    return True
