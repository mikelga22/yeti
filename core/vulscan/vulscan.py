from __future__ import unicode_literals

from mongoengine import StringField, DateTimeField, DictField, ListField, ReferenceField
from datetime import datetime
from flask_mongoengine.wtf import model_form

from core.database import Node, YetiDocument

class Vulscan(Node):
    SEARCH_ALIASES = {}

    meta = {"allow_inheritance": True}

    SCANNERS = {
        "openvas": "OpenVas"
    }

    exclude_fields = Node.exclude_fields + ["scan_date", "created", "updated", "created_by", 'results']

    name = StringField(verbose_name="Name", unique=True, max_length=1024)
    description = StringField(verbose_name="Description")
    #created_by = StringField(verbose_name="Created By")
    created = DateTimeField(default=datetime.utcnow)
    updated = DateTimeField(default=datetime.utcnow)
    scan_date = DateTimeField(verbose_name="Scan created")
    scanner = StringField(
        verbose_name="Scanner",
        choices=SCANNERS.items(),
        required=True)
    results = ListField(ReferenceField('OpenvasResult', verbose_name="Results"))

    @classmethod
    def get_form(klass, override=None):
        if override:
            klass = override
        form = model_form(klass, exclude=klass.exclude_fields)

        return form

    def info(self):
        result = self.to_mongo()

        return result

    def import_file(self, form, file, update=False):
        pass

    def save_observables(self):
        pass

    def save(self, *args, **kwargs):
        self.updated = datetime.utcnow()

        return super(Vulscan, self).save(*args, **kwargs)

class Result(YetiDocument):

    meta = {"allow_inheritance": True}

    DISPLAY_INFO=[]

    name = StringField(verbose_name="Name")
    port = StringField(verbose_name="Port")
    host = StringField(verbose_name="Host")
    information = DictField(verbose_name="Information")
