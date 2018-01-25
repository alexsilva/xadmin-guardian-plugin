from guardian.forms import UserObjectPermissionsForm, GroupObjectPermissionsForm

from xadmin.plugins.multiselect import SelectMultipleTransfer


class AdminUserObjectPermissionsForm(UserObjectPermissionsForm):
    """
    Extends :form:`UserObjectPermissionsForm`. It only overrides
    ``get_obj_perms_field_widget`` method so it return
    ``django.contrib.admin.widgets.FilteredSelectMultiple`` widget.
    """

    def get_obj_perms_field_widget(self):
        return SelectMultipleTransfer(u"", False)


class AdminGroupObjectPermissionsForm(GroupObjectPermissionsForm):
    """
    Extends :form:`UserObjectPermissionsForm`. It only overrides
    ``get_obj_perms_field_widget`` method so it return
    ``django.contrib.admin.widgets.FilteredSelectMultiple`` widget.
    """

    def get_obj_perms_field_widget(self):
        return SelectMultipleTransfer(u"", True)