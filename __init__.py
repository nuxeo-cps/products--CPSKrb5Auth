
from Products.GenericSetup import EXTENSION
from Products.GenericSetup import profile_registry
from Products.CMFCore.DirectoryView import registerDirectory

from Products.CPSCore.interfaces import ICPSSite

import Krb5Auth

registerDirectory('skins', globals())

def initialize(registrar):

    registrar.registerClass(Krb5Auth.Krb5Auth,
        constructors=(Krb5Auth.manage_addKrb5AuthForm,
                      Krb5Auth.manage_addKrb5Auth,),
        icon='krb5_auth.png',
    )

    profile_registry.registerProfile('default',
        'CPS Krb5 authentication',
        'Krb5 authentication setup for a CPS 3.4 site',
        'profiles/default',
        'CPSKrb5Auth',
        EXTENSION,
        for_=ICPSSite)

