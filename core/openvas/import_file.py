from __future__ import unicode_literals

from core.openvas.openvas import Openvas
from core.observables import Ip

def import_file(form,file):
    obj = Openvas().create(form,file)
    obj = obj.save(validate=False)
    extrac_obersrvables(obj)

    return obj

def extrac_obersrvables(obj):
    observables_to_add, links = list(), list()

    for ip in obj.hosts:
        observables_to_add.append(Ip.get_or_create(value=ip))

    obj.add(links, observables_to_add)