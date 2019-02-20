from __future__ import unicode_literals

from flask import render_template, request, flash, redirect, url_for
from core.errors import GenericValidationError, ImportVulscanError, NoImportFileError
from mongoengine import NotUniqueError

from core.web.frontend.generic import GenericView
from core.vulscan import Vulscan, Result
from core.openvas import Openvas
from core.database import AttachedFile
from core.web.helpers import requires_permissions


class VulscanView(GenericView):

    klass=Vulscan
    scanner_map = {
        "openvas": Openvas
    }

    @requires_permissions("read","vulscan")
    #@route('/result/<id>/<string:name>', methods=["GET", "POST"])
    def result(self, id, scanner):
        klass = Result
        obj = klass.objects.get(id=id)
        return render_template(
            "{}/result.html".format(scanner), obj=obj)

    @requires_permissions("read","vulscan")
    def get(self, id):
        obj = self.klass.objects.get(id=id)
        return render_template(
        "{}/single.html".format(obj.type.lower()), obj=obj)

    def post_save(self, obj, request):
        obj.save_observables()

        file=request.files.get('vulscan-file')
        if file:
            file.filename = obj.updated.strftime("%Y-%m-%d_%H:%M") + '.{}'.format(file.filename.split('.')[1])
            f = AttachedFile.from_upload(file)
            f.attach(obj)

    def handle_form(self, id=None, klass=None, skip_validation=False):
        update=False;

        if klass:  # create
            klass = self.scanner_map.get(request.form.get('scanner'))
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
                if(True):
                    obj = obj.import_file(request.files.get('vulscan-file'),update)
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

            except NoImportFileError as e:
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






