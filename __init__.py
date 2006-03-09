
import Krb5Auth

def initialize(registrar):

    registrar.registerClass(Krb5Auth.Krb5Auth,
        constructors=(Krb5Auth.manage_addKrb5AuthForm,
                      Krb5Auth.manage_addKrb5Auth,),
        icon='krb5_auth.png',
    )

