import random
import string


def str_to_bool(val):
    """Convert common yes/no true/false phrases to boolean

    Args:
        val(str): The string to convert

    Returns:
        True/False: The value of the string
        None: True/False value could not be determined

    """
    val = str(val).lower()

    if val in ['1', 'true', 'yes', 't', 'y']:
        return True
    if val in ['0', 'false', 'no', 'f', 'n', 'none', '']:
        return False

    return None


def generate_password(length=24):
    """ Generates a temporary password suitable for UAA """

    PASSWORD_SPECIAL_CHARS = ('~', '@', '#', '$', '%', '^', '*', '_', '+', '=', '-', '/', '?')

    passwordChars = string.ascii_letters + string.digits + ''.join(str(c) for c in PASSWORD_SPECIAL_CHARS)
    newPassword = str(random.choice(string.ascii_letters))
    for i in range(length - 1):
        newPassword += str(random.choice(list(passwordChars)))
    return newPassword
