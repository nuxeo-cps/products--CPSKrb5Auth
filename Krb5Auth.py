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
from zLOG import LOG, DEBUG, INFO

from Globals import InitializeClass, HTMLFile
from OFS.Folder import Folder
from OFS.Cache import Cacheable
from ZPublisher import BeforeTraverse
from Acquisition import aq_inner, aq_parent

from zope.interface import implements

try:
    import krb5
except ImportError:
    LOG("Krb5Auth", INFO, "Could not import krb5.")
    HAS_KRB5 = False
else:
    HAS_KRB5 = True

from interfaces import IKrb5Auth

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

    def __call__(self, container, request):
        """Update the request with _auth information"""
        if not HAS_KRB5:
            LOG("CPSKrb5Auth", INFO, "The krb5 module must be installed.")
            return

        cacheable = self.ZCacheable_isCachingEnabled()
        if not cacheable:
            LOG("CPSKrb5Auth", INFO,
                "The cache must be enabled on 'krb5_authentication'.")
            return

        keyset = self._computeCacheKey(request)
        ac = self.ZCacheable_get(keywords=keyset)
        if ac is not None:
            LOG("CPSKrb5Auth", DEBUG, "Got %s from the cache." % ac)
            request._auth = ac
            return

        uid, name = self._getUserInfo(request)
        password = request.get(self.pw_req_variable)

        if name is None or password is None:
            return

        if self._checkPassword(name, password):
            ac = 'CLCert %s' % encodestring(uid)
            self.ZCacheable_set(ac, keywords=keyset)
            request._auth = ac

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

    def _computeCacheKey(self, request):
        """Compute the cache key set based on host info and session id."""
        mgr = request.SESSION.getBrowserIdManager()
        browserId = mgr.getBrowserId(create=True)
        host = request.get('HTTP_X_FORWARDED_FOR')
        if not host:
            host = request.get('REMOTE_ADDR')
        return {'id': browserId, 'host': host}

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

