from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class AccountConfig(AppConfig):
    name = "allauth.account"
    label = "allauth_account"
    verbose_name = _("Accounts")
