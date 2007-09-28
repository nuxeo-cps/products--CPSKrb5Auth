##############################################################################
#
# Copyright (c) 2005 Nuxeo and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""
$Id$
"""

from base64 import encodestring
from zLOG import LOG, DEBUG, INFO, ERROR

from AccessControl import ClassSecurityInfo
from Acquisition import aq_inner, aq_parent
from Globals import InitializeClass, HTMLFile
from OFS.Folder import Folder
from OFS.Cache import Cacheable
from ZPublisher import BeforeTraverse

from Products.Sessions.BrowserIdManager import getNewBrowserId

from zope.interface import implements

try:
    import krb5
except ImportError:
    LOG("Krb5Auth", INFO, "Could not import krb5.")
    HAS_KRB5 = False
else:
    HAS_KRB5 = True

from interfaces import IKrb5Auth

SESSION_ID_VAR = '_krb5auth_id'

class Krb5Auth(Folder, Cacheable):
    """Authenticates users against krb5 without exposing the password in a
    cookie or in RAM.
    """
    meta_type = 'CPS Krb5 Auth'

    implements(IKrb5Auth)

    name_req_variable = '__ac_name'
    pw_req_variable = '__ac_password'

    manage_options = (
        Folder.manage_options +
        Cacheable.manage_options
    )

    security = ClassSecurityInfo()

    def __call__(self, container, request):
        """Update the request with _auth information.
        """
        if not HAS_KRB5:
            LOG("CPSKrb5Auth", INFO, "The krb5 module must be installed.")
            return

        # is the request authenticating?
        password = request.get(self.pw_req_variable)
        create_session = password is not None
        keyset = self._computeCacheKey(request, create_session)

        if not self.ZCacheable_isCachingEnabled():
            LOG("CPSKrb5Auth", ERROR,
                "The cache must be enabled on 'krb5_authentication'.")
            return

        ac = self.ZCacheable_get(keywords=keyset)
        if ac is not None:
            LOG("CPSKrb5Auth", DEBUG, "Got %s from the cache." % ac)
            request._auth = ac
            return

        # if the user has a session id, attempt to obtain an authorization string
        # (e.g. from a remote server)
        if keyset['id'] is not None:
            ac = self.getAuthorization(keyset)
            if ac is not None:
                LOG("CPSKrb5Auth", DEBUG, "Got an authorization string %s." % ac)

                # store the string in the local cache again
                self.ZCacheable_set(ac, keywords=keyset)
                LOG("CPSKrb5Auth", DEBUG, "Added %s to the cache." % ac)

                request._auth = ac
                return

        # authenticate the user
        uid, name = self._getUserInfo(request)
        if name is None or password is None:
            return

        if self._checkPassword(name, password):
            ac = 'CLCert %s' % encodestring(uid)
            self.ZCacheable_set(ac, keywords=keyset)
            self.storeAuthorization(keyset, ac)
            request._auth = ac

    # Public API

    security.declarePublic('expireSession')
    def expireSession(self, request):
        keyset = self._computeCacheKey(request, create=False)
        self.expireAuthorization(keyset)
        request.RESPONSE.expireCookie(SESSION_ID_VAR, path='/')

    # Extensions

    def getAuthorization(self, keyset):
        """To override: implement an authentication server, Single-Sign-On, etc.
        """
        return None

    def storeAuthorization(self, keyset, ac):
        """To override: implement an authentication server, Single-Sign-On, etc.
        """
        return

    def expireAuthorization(self, keyset):
        """To override: implement an authentication server, Single-Sign-On, etc.
        """
        return

    # Private API

    def _getUserInfo(self, request):
        """Retrieve user information from the request (typically request.form)
        """
        name = request.get(self.name_req_variable)
        if name is None:
            return None, None
        uid = name
        if '/' in name:
            uid = name.split('/')[0]
        return uid, name

    def _checkPassword(self, name, password):
        """Check that the password is correct."""
        if krb5.auth(name, password):
            return False
        return True

    def _computeCacheKey(self, request, create=False):
        """Compute the cache key set based on host info and session id."""
        sessionId = self._getSessionId(request, create)
        host = request.get('HTTP_X_FORWARDED_FOR')
        if not host:
            host = request.get('REMOTE_ADDR')
        return {'id': sessionId, 'host': host}

    def _getSessionId(self, request, create=False):
        sessionId = request.cookies.get(SESSION_ID_VAR)
        if create and sessionId is None:
            sessionId = self._createNewSessionId()
            request.RESPONSE.setCookie(SESSION_ID_VAR, sessionId)
        return sessionId

    def _createNewSessionId(self):
        # use the session manager's browser id
        return getNewBrowserId()
        
InitializeClass(Krb5Auth)

def registerHook(ob, event):
    handle = ob.meta_type + '/' + ob.getId()
    container = aq_inner(aq_parent(ob))
    nc = BeforeTraverse.NameCaller(ob.getId())
    BeforeTraverse.registerBeforeTraverse(container, nc, handle)
    LOG("CPSKrb5Auth", DEBUG, "Registered BeforeTraverse hook")

def unregisterHook(ob, event):
    handle = ob.meta_type + '/' + ob.getId()
    container = aq_inner(aq_parent(ob))
    BeforeTraverse.unregisterBeforeTraverse(container, handle)
    LOG("CPSKrb5Auth", DEBUG, "Unregistered BeforeTraverse hook")

manage_addKrb5AuthForm = HTMLFile('zmi/addKrb5Auth', globals())
manage_addKrb5AuthForm.__name__ = 'addKrb5Auth'

def manage_addKrb5Auth(self, id, REQUEST=None):
    """ """
    ob = Krb5Auth()
    ob.id = id
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST)

