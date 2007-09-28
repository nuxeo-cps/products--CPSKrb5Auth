## Script (Python) "logout"
##title=Logout handler
##parameters=

from Products.CMFCore.utils import getToolByName

# notify the event service that the user has logged out
user = context.portal_membership.getAuthenticatedMember()
if user:
    from Products.CPSCore.EventServiceTool import getPublicEventService
    evtool = getPublicEventService(context)
    evtool.notifyEvent('user_logout', user, {})

REQUEST = context.REQUEST

if REQUEST.has_key('portal_skin'):
    context.portal_skins.clearSkinCookie()

# expire the user session
uf = getToolByName(context, 'krb5_authentication', None)
if uf is not None:
    uf.expireSession(REQUEST)

return REQUEST.RESPONSE.redirect(REQUEST.URL1+'/logged_out')
