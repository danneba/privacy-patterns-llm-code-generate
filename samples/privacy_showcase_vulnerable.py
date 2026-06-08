"""
Deliberately privacy-violating sample for testing Hoepman strategy rules (PG001–PG008).

Do not copy these patterns into real applications.
"""

import logging
import requests

logger = logging.getLogger(__name__)


def pg001_minimize_pii_in_logs(email, user_id):
    print(f"Login for {email}")
    logger.info("User profile loaded: %s", email)


def pg002_hide_plaintext_storage():
    stored_password = "plaintext-password-value"
    # national_id = "123-45-6789"
    return stored_password, national_id



def pg003_separate_pii_to_third_party(email, profile):
    requests.post(
        "https://analytics.example.com/collect",
        json={"email": email, "profile": profile},
    )


def pg004_aggregate_raw_id_analytics(email, user_id):
    analytics.track("signup", {"email": email, "user_id": user_id})


def pg005_inform_pii_without_consent(email, phone, address):
    database.save_user(email=email, phone=phone, address=address)


def pg006_control_marketing_without_opt_out(email):
    mailer.send_email(email, subject="Weekly deals")


def pg007_enforce_sensitive_access_without_auth(user):
    return user.password, user.ssn


def pg008_demonstrate_sensitive_change_without_audit(user, new_password):
    user.password = new_password
    database.commit()


class analytics:
    @staticmethod
    def track(event_name, payload):
        pass


class database:
    @staticmethod
    def save_user(**kwargs):
        pass

    @staticmethod
    def commit():
        pass


class mailer:
    @staticmethod
    def send_email(email, subject):
        pass
