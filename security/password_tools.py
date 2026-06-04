"""
J.A.R.V.I.S — Password Tools
Secure password generation and strength analysis.
"""

import secrets
import string
import math
import re


class PasswordTools:
    """Generate secure passwords and analyze password strength."""

    def generate(self, length=20):
        """Generate a cryptographically secure password."""
        # Ensure at least one of each character type
        lower = secrets.choice(string.ascii_lowercase)
        upper = secrets.choice(string.ascii_uppercase)
        digit = secrets.choice(string.digits)
        special = secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?")

        # Fill the rest with random characters
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
        remaining = [secrets.choice(all_chars) for _ in range(length - 4)]

        # Combine and shuffle
        password_chars = list(lower + upper + digit + special) + remaining
        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)

        # Copy to clipboard
        try:
            import subprocess
            process = subprocess.Popen(
                ["clip"],
                stdin=subprocess.PIPE,
                shell=True
            )
            process.communicate(password.encode("utf-8"))
        except Exception:
            pass

        return (
            f"Generated a {length}-character secure password and copied it to your clipboard, sir. "
            f"The password is: {password}"
        )

    def analyze_strength(self, password):
        """Analyze password strength and return assessment."""
        score = 0
        feedback = []

        # Length check
        length = len(password)
        if length < 8:
            feedback.append("Too short. Minimum 8 characters recommended")
        elif length < 12:
            score += 1
            feedback.append("Length is acceptable but 12+ characters is stronger")
        elif length < 16:
            score += 2
        else:
            score += 3
            feedback.append("Excellent length")

        # Character variety
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/~`]", password))

        variety = sum([has_lower, has_upper, has_digit, has_special])
        score += variety

        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_special:
            feedback.append("Add special characters")
        if not has_digit:
            feedback.append("Add numbers")

        # Common patterns
        common_patterns = [
            r"12345", r"password", r"qwerty", r"abc123",
            r"letmein", r"admin", r"welcome", r"monkey",
            r"(.)\1{2,}",  # Repeated characters (aaa, 111)
            r"(012|123|234|345|456|567|678|789|890)",  # Sequential numbers
        ]

        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                score -= 2
                feedback.append("Contains common patterns — avoid dictionary words and sequences")
                break

        # Calculate entropy
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32

        if charset_size > 0:
            entropy = length * math.log2(charset_size)
        else:
            entropy = 0

        # Estimate crack time (assuming 10 billion guesses/second)
        guesses_per_sec = 10_000_000_000
        if charset_size > 0:
            total_combinations = charset_size ** length
            seconds = total_combinations / guesses_per_sec
            crack_time = self._format_time(seconds)
        else:
            crack_time = "instantly"

        # Final rating
        if score <= 1:
            rating = "VERY WEAK"
        elif score <= 3:
            rating = "WEAK"
        elif score <= 5:
            rating = "MODERATE"
        elif score <= 6:
            rating = "STRONG"
        else:
            rating = "VERY STRONG"

        msg = (
            f"Password strength: {rating}. "
            f"Entropy: {entropy:.0f} bits. "
            f"Estimated crack time: {crack_time}. "
        )

        if feedback:
            msg += "Suggestions: " + ". ".join(feedback[:3]) + "."

        return msg

    def _format_time(self, seconds):
        """Format seconds into human-readable time."""
        if seconds < 1:
            return "less than a second"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.0f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds / 31536000:.0f} years"
        elif seconds < 31536000 * 1000000:
            return f"{seconds / 31536000:.0f} years"
        else:
            return "millions of years"
