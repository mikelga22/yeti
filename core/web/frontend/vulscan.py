from __future__ import unicode_literals

from flask_classy import route
from flask_login import current_user
from flask import render_template, request, flash, redirect, url_for
from mongoengine import DoesNotExist
from core.errors import GenericValidationError, ImportVulscanError, NoImportFile
from mongoengine import NotUniqueError

from core.web.frontend.generic import GenericView
from core.vulscan import Vulscan
from core.vulscan.import_file import import_file
from core.web.helpers import get_queryset
from core.web.api.crud import CrudSearchApi
from core.web.helpers import requires_permissions


class VulscanView(GenericView):

    klass=Vulscan

    @requires_permissions("read","vulscan")
    #@route('/result/<id>/<string:name>', methods=["GET", "POST"])
    def result(self, id, name):
        if ('_' in name):
            words=name.split('_')
            name=('/').join(words)
        obj = self.klass.objects.get(id=id)
        for result in obj.results:
            if result.name==name:
                return render_template(
                    "{}/result.html".format('openvas'), obj=result)

    @requires_permissions("read","vulscan")
    def filter(self, field,value):
        return render_template(
            "{}/filter.html".format('openvas'), obj={'field':field, 'value':value})

    @requires_permissions("read","vulscan")
    def get(self, id):
        obj = self.klass.objects.get(id=id)
        return render_template(
        "{}/single.html".format(obj.type.lower()), obj=obj)

    def handle_form(self, id=None, klass=None, skip_validation=False):
        update=False;

        if klass:  # create
            obj = klass()
            form = klass.get_form()(request.form)
        else:  # update
            obj = self.klass.objects.get(id=id)
            klass = obj.__class__
            form = klass.get_form()(request.form, initial=obj._data)
            update=True

        if form.validate():
            form.populate_obj(obj)
            try:
                self.pre_validate(obj, request)
                if(not update):
                    obj = import_file(request.form, request.files.get('vulscan-file'))
                else:
                    ob=obj.save(validate=False)
                self.post_save(obj, request)
            except GenericValidationError as e:
                # failure - redirect to edit page
                form.errors['General Error'] = [e]
                return render_template(
                    "{}/edit.html".format(self.klass.__name__.lower()),
                    form=form,
                    obj_type=klass.__name__,
                    obj=None)
            except NotUniqueError as e:
                form.errors['Duplicate'] = [
                    'Object is already in the database'
                ]
                return render_template(
                    "{}/edit.html".format(self.klass.__name__.lower()),
                    form=form,
                    obj_type=klass.__name__,
                    obj=None)

            except ImportVulscanError as e:
                form.errors['Error'] = [
                    'Error importing file. Please, try again'
                ]
                return render_template(
                    "{}/edit.html".format(self.klass.__name__.lower()),
                    form=form,
                    obj_type=klass.__name__,
                    obj=None)

            except NoImportFile as e:
                form.errors['Error'] = [
                    'Not file selected. Please, select a file'
                ]
                return render_template(
                    "{}/edit.html".format(self.klass.__name__.lower()),
                    form=form,
                    obj_type=klass.__name__,
                    obj=None)

            # success - redirect to view page
            return redirect(
                url_for(
                    'frontend.{}:get'.format(self.__class__.__name__),
                    id=obj.id))
        else:
            return render_template(
                "{}/edit.html".format(self.klass.__name__.lower()),
                form=form,
                obj_type=klass.__name__,
                obj=obj)

    # @requires_permissions("write","vulscan")
    # @route('/new', methods=["GET", "POST"])
    # def new(self, klass=None):
    #     klass=self.klass
    #     if request.method == 'POST':
    #         if(request.files.get('vulscan-file')):
    #             try:
    #                 obj=import_file(request.form, request.files.get('vulscan-file'))
    #                 return redirect(
    #                     url_for(
    #                         'frontend.{}:get'.format(self.__class__.__name__),
    #                         id=obj.id))
    #             except:
    #                 flash("Error processing file", "danger")
    #         else:
    #             flash("No file selected")
    #
    #     form = klass.get_form()()
    #     obj = None
    #     return render_template(
    #         "{}/edit.html".format(self.klass.__name__.lower()),
    #         form=form,
    #         obj_type=klass.__name__,
    #         obj=obj)




