from __future__ import unicode_literals
from allauth.socialaccount import app_settings

import requests

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .provider import AzureProvider


class AzureOAuth2Adapter(OAuth2Adapter):
    """
    Docs available at:
    https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols
    """

    provider_id = AzureProvider.id
    settings = app_settings.PROVIDERS.get(provider_id, {})
    provider_default_auth_url = "https://login.microsoftonline.com/{}/oauth2/v2.0".format(
        settings.get("TENANT", 'common')
    )
    provider_default_graph_url = "https://graph.microsoft.com/v1.0"

    access_token_url = provider_default_auth_url + "/token"
    authorize_url = provider_default_auth_url + "/authorize"
    profile_url = provider_default_auth_url + "/me"
    
    # Can be used later to obtain group data. Needs 'Group.Read.All' or
    # similar.
    #
    # See https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/api/user_list_memberof  # noqa
    groups_url = provider_default_graph_url + "/me/memberOf?$select=displayName"

    def complete_login(self, request, app, token, **kwargs):
        headers = {"Authorization": "Bearer {0}".format(token.token)}
        extra_data = {}

        resp = requests.get(self.profile_url, headers=headers)

        # See:
        #
        # https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/user_get  # noqa
        #
        # example of what's returned (in python format)
        #
        # {u'displayName': u'John Smith', u'mobilePhone': None,
        #  u'preferredLanguage': u'en-US', u'jobTitle': u'Director',
        #  u'userPrincipalName': u'john@smith.com',
        #  u'@odata.context':
        #  u'https://graph.microsoft.com/v1.0/$metadata#users/$entity',
        #  u'officeLocation': u'Paris', u'businessPhones': [],
        #  u'mail': u'john@smith.com', u'surname': u'Smith',
        #  u'givenName': u'John', u'id': u'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}

        profile_data = resp.json()
        extra_data.update(profile_data)

        return self.get_provider().sociallogin_from_response(request, extra_data)


oauth2_login = OAuth2LoginView.adapter_view(AzureOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(AzureOAuth2Adapter)
