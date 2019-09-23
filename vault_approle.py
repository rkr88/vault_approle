"""Module to connect to HashiCorp Vault using approle and fetch the secrets
stored in a given path

This module accepts Approle's role-id and secret-id in base64 encode format
"""
import warnings
import base64
import hvac


class Vault(object):
    """Class to connect to HashiCorp Vault
    """

    def __init__(self, host, roleid, secretid, port=8200, timeout=20,
                 sslverify=True):
        """initializing the vault module

        ARGS:
            host: Vault's hostname
            port: Vault's port number. Default is 8200
            roleid: Approle role-id in base64 encoded format
            secertid: Approle secret-id in base64 encoded format
            timeout: timeout period. Default is 20 sec
            sslverify: SSL certificate verification. Default is True
        """
        self._host = host
        self._port = port
        self._roleid = roleid
        self._secretid = secretid
        self._sslverify = sslverify
        self._timeout = timeout

        if self._sslverify is False:
            # Ignore self-signed certificate warnings.
            warnings.simplefilter("ignore")

        self._url = "https://{}:{}".format(self._host, self._port)

        self._client = hvac.Client(
            url=self._url,
            verify=self._sslverify,
            timeout=self._timeout
        )

        # Decode roleid and secretid
        roleid, secretid = self._get_login_id(
            self._roleid,
            self._secretid
        )

        # Connect to vault using approle
        self._client.auth_approle(roleid, secretid)

    def get_secret(self, path):
        """Function to connect to the vault

        ARGS:
            path: Path name from where credentials has to be fetched

        RETURNS:
            dictionary containing the path data and error, if any
        """
        try:
            result = self._client.read(path)
            if result is None:
                data = None
                error = "No secrets stored in mentioned path"
            else:
                data = result['data']
                error = None
        except Exception as err:
            data = None
            if str(err) == "Vault is sealed":
                error = "Vault is sealed. Got error: {}".format(err)
            else:
                error = "Unable to fetch the data. Got error : {}".format(err)

        return {'Data': data, 'Error': error}

    def _get_login_id(self, roleid, secretid):
        """
        """
        roleid = base64.b64decode(roleid).decode('ascii')
        secretid = base64.b64decode(secretid).decode('ascii')
        return roleid, secretid
