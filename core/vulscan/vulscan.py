from __future__ import unicode_literals

from mongoengine import StringField, DateTimeField
from datetime import datetime
from flask_mongoengine.wtf import model_form
from flask import url_for

from core.database import Node, TagListField, EntityListField
from core.observables import Tag


class Vulscan(Node):
    SEARCH_ALIASES = {}

    meta = {"allow_inheritance": True}

    SCANNERS = {
        "openvas": "OpenVas"
    }

    exclude_fields = Node.exclude_fields + ["scan_date", "created", "updated", "created_by"]

    name = StringField(verbose_name="Name", max_length=1024)
    description = StringField(verbose_name="Description")
    created_by = StringField(verbose_name="Created By")
    created = DateTimeField(default=datetime.utcnow)
    updated = DateTimeField(default=datetime.utcnow)
    scan_date = DateTimeField(verbose_name="Scan date")
    scanner = StringField(
        verbose_name="Scanner",
        choices=SCANNERS.items(),
        required=True)

    @classmethod
    def get_form(klass, override=None):
        if override:
            klass = override
        form = model_form(klass, exclude=klass.exclude_fields)

        return form

    def info(self):
        result = self.to_mongo()

        return result
