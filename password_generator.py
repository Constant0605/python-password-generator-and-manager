import string
import random
import re

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(self, length=12, use_uppercase=True, use_digits=True, use_special=True):
        """Generate a password based on specified criteria."""
        characters = self.lowercase

        if use_uppercase:
            characters += self.uppercase
        if use_digits:
            characters += self.digits
        if use_special:
            characters += self.special_chars

        password = ''.join(random.choice(characters) for _ in range(length))
        
        if use_uppercase:
            password = self._ensure_character_type(password, self.uppercase)
        if use_digits:
            password = self._ensure_character_type(password, self.digits)
        if use_special:
            password = self._ensure_character_type(password, self.special_chars)

        return password

    def _ensure_character_type(self, password, char_set):
        """Ensure password contains at least one character from the given set."""
        if not any(c in char_set for c in password):
            position = random.randint(0, len(password) - 1)
            password = password[:position] + random.choice(char_set) + password[position + 1:]
        return password

    def check_password_strength(self, password):
        """Check password strength and return a score and feedback."""
        score = 0
        feedback = []

        if len(password) < 8:
            feedback.append("Password is too short")
        elif len(password) >= 12:
            score += 2
            feedback.append("Good length")
        else:
            score += 1

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add numbers")

        if re.search(r"[!@#$%^&*()_+\-=\[\]{};:,.<>?]", password):
            score += 1
        else:
            feedback.append("Add special characters")

        if score < 2:
            strength = "Very Weak"
        elif score < 3:
            strength = "Weak"
        elif score < 4:
            strength = "Moderate"
        elif score < 5:
            strength = "Strong"
        else:
            strength = "Very Strong"

        if not feedback:
            feedback.append("Password meets all criteria")

        return {
            'score': score,
            'strength': strength,
            'feedback': feedback
        } 