# Mixed Python 2/3 features to force version-aware parsing and semantics
from __future__ import print_function

def divide(a, b):
    return a / b  # integer vs float division depends on interpreter

result = divide(3, 2)

print('py3-style print keeps working, but beware of:')
print result  # Python 2 statement form is a syntax error in Python 3

# Python 3-only syntax below; Python 2 should choke before reaching it
def greet(name: str) -> str:
    return f"hello {name}"
