from __future__ import unicode_literals

import re
from mongoengine import *
from flask_mongoengine.wtf import model_form
from core.database import YetiDocument, AttachedFile
from flask import url_for
from core.investigation import Investigation
import xml.etree.ElementTree as ET
from datetime import datetime


class Result(EmbeddedDocument):
    name=StringField()
    port=StringField()
    threat=StringField()
    severity=DecimalField()
    qod=IntField()
    description=StringField()


    def create(self, res):
        self.name=res.find('name').text
        self.port=res.find('port').text
        self.threat=res.find('threat').text
        self.severity=res.find('severity').text
        self.qod=res.find('qod').find('value').text
        self.description=" ".join(re.split("\s+", res.find('description').text, flags=re.UNICODE))
        #self.nvt=Nvt(res.find('nvt'))

        return self

class Openvas (Investigation):
    oid=StringField(verbose_name="OID")
    name=StringField(verbose_name="Name")
    report_date=DateTimeField(verbose_name="Date of report")
    host=StringField(verbose_name="Host")
    ports=StringField(verbose_name="Ports")
    results_count=IntField(verbose_name="Rresults count")
    severity=DecimalField(verbose_name="Severity")
    results=ListField(EmbeddedDocumentField(Result), verbose_name="Results")

    exclude_fields = ['links', 'nodes', 'events', 'created', 'updated', 'created_by',
                      'import_document', 'import_md', 'import_url', 'import_text',
                      'report_date','host','ports','results_count','severity','results','oid']



    def import_file(self, form, f):
        file = ET.parse(f)
        report = file.getroot().find('report')
        self.created_by=form.get('created_by')
        self.description=form.get('description')
        self.oid=file.getroot().attrib.values()[3]
        if form.get('name'):
            self.name=form.get('name')
        else:
            self.name = file.getroot().find('name').text
        self.report_date = datetime.strptime(file.getroot().find('creation_time').text,'%Y-%m-%dT%H:%M:%SZ')
        self.host = report.find('host').find('ip').text
        self.ports = ""
        for port in report.find('ports').findall('port'):
            self.ports += port.text + ","
        self.ports = self.ports[:-1].replace('\n', '').replace(' ', '')
        self.results_count = report.find('result_count').find('filtered').text
        self.severity = report.find('severity').find('filtered').text

        for r in report.find('results'):
            result=Result().create(r)
            self.results.append(result)

        return self;
