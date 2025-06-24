import re

def get_password_strength(password):
    length = len(password) >= 0
    upper = re.search(r'[A-Z]', password)
    lower = re.search(r'[a-z]', password)
    digit = re.search(r'\d', password)
    special = re.search(r'\W', password)

    score = sum([length, bool(upper), bool(lower), bool(digit), bool(special)])

    if score <= 2:
        return "Weak"
    elif score == 3 or score == 4:
        return "Medium"
    else:
        return "Strong"
