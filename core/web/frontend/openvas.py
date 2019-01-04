from __future__ import unicode_literals

from flask_classy import route
from flask_login import current_user
from flask import render_template, request, flash, redirect, url_for
from mongoengine import DoesNotExist

from core.web.frontend.investigations import InvestigationView
from core.openvas import Openvas
from core.openvas.import_file import import_file
from core.web.helpers import get_queryset
from core.web.api.crud import CrudSearchApi
from core.web.helpers import requires_permissions


class OpenvasView(InvestigationView):

    @requires_permissions("read")
    #@route('/<result>', methods=["GET", "POST"])
    def result(self, id, name):
        obj = self.klass.objects.get(id=id)
        result=""
        for r in obj.results:
            if r.name==name:
                return render_template(
                    "{}/result.html".format('openvas'), obj=r)

    @requires_permissions("read")
    def filter(self, field,value):
        return render_template(
            "{}/filter.html".format('openvas'), obj={'field':field, 'value':value})

    @requires_permissions("read")
    def get(self, id):
        obj = self.klass.objects.get(id=id)
        return render_template(
        "{}/single.html".format(obj.type.lower()), obj=obj)

    @requires_permissions("write")
    @route('/new', methods=["GET", "POST"])
    def new(self, klass=None):
        klass = Openvas
        if request.method == 'POST':
            obj=import_file(request.form, request.files.get('openvas-file'))
            return redirect(
                url_for(
                    'frontend.{}:get'.format(self.__class__.__name__),
                    id=obj.id))

        form = klass.get_form()()
        obj = None
        return render_template(
            "{}/edit.html".format(klass.__name__.lower()),
            form=form,
            obj_type=klass.__name__,
            obj=obj)



