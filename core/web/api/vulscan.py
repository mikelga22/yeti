from __future__ import unicode_literals

from core import vulscan
from core.web.api.crud import CrudSearchApi, CrudApi
from core.web.helpers import get_queryset

class VulscanSearch(CrudSearchApi):
    template = 'vulscan_api.html'
    objectmanager = vulscan.Vulscan


class Vulscan(CrudApi):
    template = 'vulscan_api.html'
    objectmanager = vulscan.Vulscan