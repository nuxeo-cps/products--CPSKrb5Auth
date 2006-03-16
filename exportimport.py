
"""Krb5 authentication xml adapters and setup handlers.
"""

from Products.GenericSetup.utils import exportObjects
from Products.GenericSetup.utils import importObjects
from Products.GenericSetup.utils import PropertyManagerHelpers
from Products.GenericSetup.utils import ObjectManagerHelpers
from Products.GenericSetup.utils import XMLAdapterBase

from Products.CMFCore.utils import getToolByName

from Products.CPSUtil.cachemanagersetup import CacheableHelpers

from interfaces import IKrb5Auth

class Krb5AuthXMLAdapter(XMLAdapterBase, ObjectManagerHelpers,
                         PropertyManagerHelpers, CacheableHelpers):
    """XML im- and exporter for Krb5Auth.
    """
    __used_for__ = IKrb5Auth

    _LOGGER_ID = 'krb5auth'

    name = 'krb5auth'

    def _exportNode(self):
        """Export the object as a DOM node.
        """
        node = self._getObjectNode('object')
        node.appendChild(self._extractProperties())
        node.appendChild(self._extractObjects())

        child = self._extractCacheableManagerAssociation()
        if child is not None:
            node.appendChild(child)

        self._logger.info('Krb5 authentication exported.')
        return node

    def _importNode(self, node):
        """Import the object from the DOM node.
        """
        if self.environ.shouldPurge():
            self._purgeProperties()
            self._purgeObjects()
            self._purgeCacheableManagerAssociation()

        self._initProperties(node)
        self._initObjects(node)
        self._initCacheableManagerAssociation(node)

        self._logger.info('Krb5 authentication imported.')

def importKrb5Auth(context):
    """Import krb5 auth settings from an XML file.
    """
    site = context.getSite()
    tool = getToolByName(site, 'krb5_authentication')
    importObjects(tool, '', context)

def exportKrb5Auth(context):
    """Export krb5 auth settings as an XML file.
    """
    site = context.getSite()
    tool = getToolByName(site, 'krb5_authentication', None)
    if tool is None:
        logger = context.getLogger('krb5auth')
        logger.info('Nothing to export.')
        return
    exportObjects(tool, '', context)
