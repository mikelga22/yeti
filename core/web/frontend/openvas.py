from __future__ import unicode_literals

from flask import render_template

from core.web.frontend.vulscans import VulscanView
from core.vulscan import Vulscan, Result
from core.web.helpers import requires_permissions

class OpenvasView(VulscanView):
    @requires_permissions("read", "vulscan")
    # @route('/result/<id>/<string:name>', methods=["GET", "POST"])
    def result(self, id):
        klass=Result
        obj = klass.objects.get(id=id)
        return render_template(
                    "{}/result.html".format('openvas'), obj=obj)