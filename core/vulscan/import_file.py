from core.openvas import OpenvasImport

def import_file(form,file):

    scanner_map = {
        "openvas": OpenvasImport
    }

    klass=scanner_map.get(form.get('scanner'))
    obj=klass().import_file(form,file)
    return obj