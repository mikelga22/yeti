from __future__ import unicode_literals

from flask_classy import route
from flask_login import current_user
from flask import render_template, request, flash, redirect, url_for
from mongoengine import DoesNotExist

from core.web.frontend.vulscans import VulscanView
from core.vulscan import Vulscan, Result
from core.web.helpers import get_queryset
from core.web.api.crud import CrudSearchApi
from core.web.helpers import requires_permissions

class OpenvasView(VulscanView):
    @requires_permissions("read", "vulscan")
    # @route('/result/<id>/<string:name>', methods=["GET", "POST"])
    def result(self, id):
        klass=Result
        obj = klass.objects.get(id=id)
        return render_template(
                    "{}/result.html".format('openvas'), obj=obj)