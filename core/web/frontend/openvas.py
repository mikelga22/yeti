from __future__ import unicode_literals

from flask_classy import route
from flask_login import current_user
from flask import render_template, request, flash, redirect, url_for
from mongoengine import DoesNotExist

from core.web.frontend.vulscan import VulscanView
from core.vulscan import Vulscan
from core.vulscan.import_file import import_file
from core.web.helpers import get_queryset
from core.web.api.crud import CrudSearchApi
from core.web.helpers import requires_permissions

class OpenvasView(VulscanView):
    @requires_permissions("read", "vulscan")
    # @route('/result/<id>/<string:name>', methods=["GET", "POST"])
    def result(self, id, name):
        if ('_' in name):
            words = name.split('_')
            name = ('/').join(words)
        obj = self.klass.objects.get(id=id)
        for result in obj.results:
            if result.name == name:
                return render_template(
                    "{}/result.html".format('openvas'), obj=result)