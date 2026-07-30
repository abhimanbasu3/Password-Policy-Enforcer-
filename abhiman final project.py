import re
import hashlib
import requests
import json # Built-in library to read/write JSON files
import os   # Built-in library to check if a file exists
import random # Added for password generator
import string # Added for password generator

# The name of our database file
DB_FILE = "database.json"

def setup_database():
    """
    Checks if the JSON database exists. If not, it creates a starter file.
    """
    if not os.path.exists(DB_FILE):
        starting_data = {
            "blocklist": ["password123", "admin123", "qwerty", "12345678", "letmein1!"],
            "users": [] # This empty list will hold our saved users
        }
        # Create the file and write the starting data into it
        with open(DB_FILE, "w") as file:
            json.dump(starting_data, file, indent=4)

def load_blocklist():
    """
    Opens the JSON database and returns just the blocklist array.
    """
    with open(DB_FILE, "r") as file:
        data = json.load(file)
        return data["blocklist"]

def save_new_user(username, email, password):
    """
    Saves a new user to the JSON database securely.
    """
    # 1. Read the current data from the database
    with open(DB_FILE, "r") as file:
        data = json.load(file)
    
    # 2. CYBERSECURITY BEST PRACTICE: Hash the password before saving it!
    # We use SHA-256 here for local storage security.
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # 3. Create a dictionary for the new user
    new_user = {
        "username": username,
        "email": email,
        "password_hash": hashed_pw
    }
    
    # 4. Add the new user to our list and save the whole file again
    data["users"].append(new_user)
    with open(DB_FILE, "w") as file:
        json.dump(data, file, indent=4)

def check_pwned_password(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = hashed_password[:5]
    suffix = hashed_password[5:]
    
    url = "https://api.pwnedpasswords.com/range/" + prefix
    response = requests.get(url)
    
    if response.status_code != 200:
        return -1 
        
    hashes = response.text.splitlines()
    for line in hashes:
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count) 
            
    return 0 

def check_leetspeak(password):
    """
    Translates common leetspeak characters back to standard letters
    to catch attempts to bypass the blocklist (e.g., P@$$w0rd -> password).
    """
    leetspeak_map = {
        '@': 'a',
        '$': 's',
        '0': 'o',
        '1': 'i',
        '!': 'i',
        '3': 'e',
        '5': 's',
        '+': 't'
    }
    translated = password.lower()
    for leet, letter in leetspeak_map.items():
        translated = translated.replace(leet, letter)
    return translated

def detect_keyboard_walks(password):
    """
    Checks if the password contains common keyboard dragging patterns.
    """
    walks = ["qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx"]
    for walk in walks:
        if walk in password.lower():
            return True
    return False

def detect_common_years(password):
    """
    Looks for recent years (1900-2029) to catch predictable number additions.
    """
    if re.search(r"(19\d{2}|20[0-2]\d)", password):
        return True
    return False

def check_repetitions(password):
    """
    Checks if a character is lazily repeated 3 or more times in a row.
    """
    if re.search(r"(.)\1{2,}", password):
        return True
    return False

def validate_password(password, username, email):
    errors = [] 
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Must have at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Must have at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Must have at least one number.")
    if not re.search(r"[!@#$%^&*]", password):
        errors.append("Must have at least one special character (!@#$%^&*).")
        
    if username.lower() in password.lower():
        errors.append("Your password cannot contain your username.")
    if email.lower() in password.lower():
        errors.append("Your password cannot contain your email.")
        
    if detect_keyboard_walks(password):
        errors.append("Password contains a predictable keyboard pattern (e.g., 'qwerty' or '123456').")
    if detect_common_years(password):
        errors.append("Try not to use birth years or current years, hackers guess these first.")
    if check_repetitions(password):
        errors.append("Password contains repeated characters (like 'aaa' or '111') which are easy to guess.")
        
    # --- JSON DATABASE INTEGRATION ---
    # We now pull the blocked words directly from database.json
    blocklist = load_blocklist()
    translated_password = check_leetspeak(password)
    
    if password.lower() in blocklist or translated_password in blocklist:
        errors.append("This password is too common and is blocked by our database (or uses common substitutions).")

    if len(errors) == 0:
        breaches = check_pwned_password(password)
        if breaches > 0:
            errors.append(f"Password found in {breaches} data breaches! Pick a new one.")
        elif breaches == -1:
            errors.append("Error connecting to the breach database.")

    return errors

def calculate_strength(password):
    """
    Calculates a strength score on a scale of 1 to 10 based on length and character variety.
    """
    score = 0
    
    # Length points (up to 5)
    if len(password) >= 8: score += 2
    if len(password) >= 12: score += 2
    if len(password) >= 16: score += 1
    
    # Character variety points (up to 5)
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*]", password): score += 2
    
    # Cap score at 10 just in case
    score = min(score, 10)
    
    # Determine the text label
    if score <= 3:
        label = "Weak"
    elif score <= 6:
        label = "Moderate"
    elif score <= 8:
        label = "Strong"
    else:
        label = "Very Strong"
        
    return f"{score}/10 ({label})"

def estimate_crack_time(password):
    """
    Estimates how long it would take a hacker to brute-force the password.
    """
    pool_size = 0
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"[0-9]", password): pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool_size += 32
    
    if pool_size == 0 or len(password) == 0:
        return "Instantly"
        
    # Total possible combinations for this length and character pool
    combinations = pool_size ** len(password)
    
    # Assuming a hacker can try 10 billion passwords per second (offline attack)
    guesses_per_second = 10_000_000_000 
    seconds = combinations / guesses_per_second
    
    if seconds < 1: return "Less than a second"
    elif seconds < 60: return f"{int(seconds)} seconds"
    elif seconds < 3600: return f"{int(seconds / 60)} minutes"
    elif seconds < 86400: return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000: return f"{int(seconds / 86400)} days"
    elif seconds < 3153600000: return f"{int(seconds / 31536000)} years"
    else: return "Centuries"

def generate_secure_password(length=16):
    """
    Generates a secure password that passes all validation rules.
    """
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(random.choice(characters) for _ in range(length))
        # Ensure it has at least one of every required character type
        if (re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[!@#$%^&*]", password)):
            return password

def generate_passphrase():
    """
    Generates a memorable, highly secure XKCD-style passphrase.
    """
    words = ["Purple", "Dragon", "Fly", "River", "Cloud", "Rocket", "Shadow", "Winter", "Tiger", "Mountain", "Neon", "Cyber", "Ninja", "Cosmic", "Ocean"]
    # Pick 3 random words and attach a random number and symbol at the end
    passphrase = f"{random.choice(words)}-{random.choice(words)}-{random.choice(words)}{random.randint(10, 99)}!"
    return passphrase

# --- MAIN PROGRAM STARTS HERE ---
# First thing we do is make sure our database file is ready!
setup_database()

print("=======================================")
print("      Password Security Checker        ")
print("=======================================")
print("Let's set up your profile first.")

username = input("Enter your username: ")
email = input("Enter your email: ")

print("\n--- Testing Area ---")
print("Type 'exit' to stop the program.")

while True:
    test_password = input("\nEnter a password to test: ")
    
    if test_password == "exit":
        print("Goodbye!")
        break
        
    found_errors = validate_password(test_password, username, email)
    strength = calculate_strength(test_password)
    crack_time = estimate_crack_time(test_password)
    
    if len(found_errors) > 0:
        print("\n[X] PASSWORD REJECTED")
        print(f"Calculated Strength: {strength}")
        print(f"Estimated Crack Time: {crack_time}")
        print("Reasons:")
        for error in found_errors:
            print("- " + error)
            
        print(f"\nSuggestion 1 (Random): Try a secure password like -> {generate_secure_password()}")
        print(f"Suggestion 2 (Memorable): Or try a passphrase like -> {generate_passphrase()}")
    else:
        print("\n[✓] PASSWORD ACCEPTED")
        print(f"Calculated Strength: {strength}")
        print(f"Estimated Crack Time: {crack_time}")
        print("Great job! Your password is secure and passes all checks.")
        
        # --- JSON DATABASE INTEGRATION ---
        # Save the successful user to the database
        save_new_user(username, email, test_password)
        print("-> User profile and securely hashed password saved to database.json!")
        
        # End the loop because they successfully registered
        break