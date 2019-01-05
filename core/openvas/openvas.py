from __future__ import unicode_literals

import re
from mongoengine import *
from flask_mongoengine.wtf import model_form
from core.database import YetiDocument, AttachedFile
from flask import url_for
from core.investigation import Investigation
import xml.etree.ElementTree as ET
from datetime import datetime
import re


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

    def info(self):
        result = self.to_mongo()
        result['nvt']=self.nvt

        return result

class Nvt(YetiDocument):

    DISPLAY_INFO = [("summary", "Summary"), ("impact", "Impact"), ("affected", "Affected Software/OS"), ("insight", "Vulnerability Insight"), ("insight", "Vulnerability insight"), ("solution", "Solution"), ("vuldetect", "Vulnerability detection method")]

    oid = StringField(verbose_name="OID", unique=True)
    name=StringField(verbose_name="Name")
    family=StringField(verbose_name="Family")
    references=ListField(verbose_name="References")
    information=DictField(verbose_name="Information")
    certs=ListField(verbose_name="Certs")
    cves=ListField(verbose_name="CVE")


    def create(self,nvt):

        self.oid = nvt.attrib.values()[0]

        try:
            obj=Nvt.objects.get(oid=self.oid)
        except DoesNotExist:
            self.name = nvt.find('name').text
            self.family = nvt.find('family').text

            self.extract_references(nvt.find('xref').text)
            self.extract_information(nvt.find('tags').text)
            self.extract_cves(nvt.find('cve').text)
            self.extract_certs(nvt.find('cert'))
            obj = self.save()

        return obj

    def extract_certs(self, certs):
        list=[]
        for cert in certs:
            list.append(cert.attrib.values()[1])
        if len(list)==0:
            return None

        self.certs=list

    def extract_cves(self, cves):
        if(cves!='NOCVE'):
            list=cves.split(', ')

            self.cves=list

    def extract_references(self, references):
        list=re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', references)

        self.references=list

    def extract_information(self,tags):
        e = {}
        for element in tags.split('|'):
            element=element.split('=')
            if(len(element)>2):
                list_temp=[]
                for i in range(1, len(element)):
                    list_temp.append(element[i])
                element[1]=('=').join(list_temp)
            e[element[0]]=element[1]

        self.information=e

    def info(self):
        result = self.to_mongo()

        return result


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

    def create(self, form, f):
        file = ET.parse(f)
        report = file.getroot().find('report')
        self.created_by=form.get('created_by')
        self.description=form.get('description')
        self.oid=file.getroot().attrib.values()[3]
        if form.get('name'):
            self.name=form.get('name')
        else:
            self.name = 'Openvas({})'.format(file.getroot().find('name').text)
        self.report_date = datetime.strptime(file.getroot().find('creation_time').text,'%Y-%m-%dT%H:%M:%SZ')
        self.results_count = report.find('result_count').find('filtered').text
        self.severity = report.find('severity').find('filtered').text

        self.extract_hosts(report.findall('host'))
        self.extract_ports(report.find('ports').findall('port'))
        self.extract_results(report.find('results'))

        return self

    def extract_hosts(self,hosts):
        list=[]
        for host in hosts:
            ip=host.find('ip').text
            list.append(ip)

            # for detail in host.findall('detail'):
            #     if (detail.find('name').text.lower()=='os-detection'):
            #         os=detail.find('value').text
            #         list.append({'host':ip,'os':os})
            #         print(os)

        self.hosts=list

    def extract_ports(self,ports):
        list=[]
        for port in ports:
            list.append(port.text)

        self.ports=list

    def extract_results(self, results):
        list=[]

        for r in results:
            result=Result().create(r)
            list.append(result)

        self.results=list
