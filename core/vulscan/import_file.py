from core.openvas import Openvas
from core.errors import ImportVulscanError, NoImportFile
from mongoengine import NotUniqueError

def import_file(form,file,update=False):


    if (not file and not update):
        raise NoImportFile("No file found")

    scanner_map = {
        "openvas": Openvas
    }

    try:
        klass=scanner_map.get(form.get('scanner'))
        obj=klass().import_file(form,file)
        return obj
    except NotUniqueError as e:
        raise NotUniqueError()
    except Exception as e:
        raise ImportVulscanError("Error importing file")