# xadmin-guardian-plugin
Plugin that implement the guardian support in xadmin.



## Install

python -m pip install git+https://github.com/alexsilva/xadmin.plugin.guardian.git


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
from xplugin_guardian.admin import GuardianPlugin


# displays a button in the view when editing a model.
site.register_plugin(GuardianPlugin, ModelAdminView)


# Activate the plugin in this view (guarded_model = True)

class MyModelAdmin(object):
    guarded_model = True   # protected by guardian
    

# Replace MyModel with your model

site.register(MyModel, MyModelAdmin)
```
