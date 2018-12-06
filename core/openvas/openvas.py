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
    host=StringField()
    threat=StringField()
    severity=DecimalField()
    qod=IntField()
    description=StringField()
    nvt=ReferenceField('Nvt')


    def create(self, res):
        self.name=res.find('name').text
        self.host = res.find('host').text
        self.port=res.find('port').text
        self.threat=res.find('threat').text
        self.severity=res.find('severity').text
        self.qod=res.find('qod').find('value').text
        self.description=res.find('description').text if res.find('description') is not None else None
        self.description=self.description.split('\n') if self.description is not None else None
        self.nvt=Nvt().create(res.find('nvt')).id

        return self

class Nvt(Document):
    # oid=StringField(verbose_name="OID", unique=True
    oid = StringField(verbose_name="OID")
    name=StringField(verbose_name="Name")
    references=ListField(verbose_name="References")
    info=ListField(verbose_name="Information")
    certs=ListField(verbose_name="Certs")
    cve=StringField(verbose_name="CVE")


    def create(self,nvt):
        self.oid=nvt.attrib.values()[0]
        self.name = nvt.find('name').text
        self.references=[]
        self.references = nvt.find('xref').text.split('\n')
        #self.info=[]
        self.info=nvt.find('tags').text.split('|')
        self.cve = nvt.find('cve').text.replace(' ', '')
        #self.certs=[]
        self.certs=self.get_certs(nvt.find('cert'))

        obj=self.save()
        # try:
        #     obj=Nvt.objects.get(oid=self.oid)
        # except DoesNotExist:
        #     obj=self.save()

        return obj

    def get_certs(self, certs):
        list=[]
        for cert in certs:
            list.append(cert.attrib.values()[0])
        return list

    def get_tags(self,tags):
        list=[]=tags.split('|')
        return list


class Openvas (Investigation):
    oid=StringField(verbose_name="OID")
    name=StringField(verbose_name="Name")
    report_date=DateTimeField(verbose_name="Date of report")
    hosts=ListField(verbose_name="Host")
    ports=ListField(verbose_name="Ports")
    results_count=IntField(verbose_name="Rresults count")
    severity=DecimalField(verbose_name="Severity")
    results=ListField(EmbeddedDocumentField(Result), verbose_name="Results")

    exclude_fields = Investigation.exclude_fields+['report_date','hosts','ports','results_count','severity','results','oid']



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

        for h in report.findall('host'):
            self.hosts.append(h.find('ip').text)
        # self.host = report.find('host').find('ip').text
        #self.hosts = self.hosts[:-2].replace('\n', '')

        for port in report.find('ports').findall('port'):
            self.ports.append(port.text)
        #.ports = self.ports[:-2].replace('\n', '')#.replace(' ', '')
        self.results_count = report.find('result_count').find('filtered').text
        self.severity = report.find('severity').find('filtered').text

        for r in report.find('results'):
            result=Result().create(r)
            self.results.append(result)

        return self;

    def get_hosts(self,hosts):
        pass
