# xadmin-guardian-plugin
Plugin that implement the guardian support in xadmin.


## Requirements
Python 3

Django 2+

Xadmin `https://github.com/alexsilva/django-xadmin` branch `bs4_dj2`

## Install

python -m pip install git+https://github.com/alexsilva/xadmin.plugin.guardian.git@bs4_dj2


## Add to installed apps:

INSTALLED_APPS = [
    ...,
    "xplugin_guardian"
]



## In your `adminx.py`, register the plugin:

```
from xadmin.views import ModelAdminView
from xadmin.sites import site

# plugin registry
import xplugin_guardian.plugin

# register views
xplugin_guardian.plugin.register_views(site)


# Activate the plugin in this view (guarded_model = True)
class MyModelAdmin:
    guardian_permissions = True   # protected by guardian


# Replace MyModel with your model

site.register(MyModel, MyModelAdmin)
```
