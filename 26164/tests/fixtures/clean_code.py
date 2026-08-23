# Clean Python code with zero cryptography
def calculate_factorial(n: int) -> int:
    if n <= 1:
        return 1
    return n * calculate_factorial(n - 1)

class SimpleUser:
    def __init__(self, username: str, email: str):
        self.username = username
        self.email = email

    def get_display_name(self) -> str:
        return f"{self.username} <{self.email}>"
