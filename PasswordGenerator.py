from secrets import choice, SystemRandom

def generate_password(length : int, reqUpper : bool, reqLower : bool, reqNum : bool, reqSpecial : bool, reqAltSpecial : bool):
    # Generates a password with given requirements by the user and returns the string password generated

    # Make a list of our avaiable characters for password creation
    ALPHA = list("abcdefghijklmnopqrstuvwxyz")
    NUMS = list("1234567890")
    SPECIAL = list("!@#$%^&*(_-+=")
    ALT_SPECIAL = list("~`/\\|[{]}:;\"'<>,.?")

    # If the user requires a specific set of characters in their password that is less than length we return an error
    if length < reqUpper + reqLower + reqNum + reqSpecial + reqAltSpecial:
        raise ValueError("Password generation failed as user required more characters than provided length.")

    USEABLE_CHARS = []
    password = []
    if reqUpper:
        password.append(choice(ALPHA).upper())
        for i in range(len(ALPHA)):
            USEABLE_CHARS.append(ALPHA[i].upper())
    if reqLower:
        password.append(choice(ALPHA))
        for i in range(len(ALPHA)):
            USEABLE_CHARS.append(ALPHA[i])
    if reqNum:
        password.append(choice(NUMS))
        USEABLE_CHARS += NUMS
    if reqSpecial:
        password.append(choice(SPECIAL))
        USEABLE_CHARS += SPECIAL
    if reqAltSpecial:
        password.append(choice(ALT_SPECIAL))
        USEABLE_CHARS += ALT_SPECIAL

    while len(password) < length:
        password.append(choice(USEABLE_CHARS))
    
    SystemRandom().shuffle(password)
    return "".join(password)