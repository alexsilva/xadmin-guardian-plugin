from __future__ import unicode_literals

from collections import OrderedDict

import django
from django.conf import settings
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render_to_response, render
from django.template import RequestContext
from django.utils.translation import ugettext
from django.utils.translation import ugettext_lazy as _
from guardian.admin import (
    AdminGroupObjectPermissionsForm,
    UserManage,
    GroupManage,
    AdminUserObjectPermissionsForm
)
from guardian.compat import (
    get_model_name,
    get_user_model,
    url,
    reverse
)
from guardian.models import Group
from guardian.shortcuts import (
    get_group_perms,
    get_groups_with_perms,
    get_perms_for_model,
    get_user_perms,
    get_users_with_perms
)
from xadmin.views import BaseAdminPlugin


class GuardianPlugin(BaseAdminPlugin):
    """
    Xadmin plugin
    """

    change_form_template = 'xplugin_guardian/guardian/model/change_form.html'
    obj_perms_manage_template = 'xplugin_guardian/guardian/model/obj_perms_manage.html'
    obj_perms_manage_user_template = 'xplugin_guardian/guardian/model/obj_perms_manage_user.html'
    obj_perms_manage_group_template = 'xplugin_guardian/guardian/model/obj_perms_manage_group.html'

    user_can_access_owned_objects_only = False

    user_owned_objects_field = 'user'

    user_can_access_owned_by_group_objects_only = False

    group_owned_objects_field = 'group'

    include_object_permissions_urls = True

    def init_request(self, *args, **kwargs):
        return getattr(self, 'guarded_model', False)

    def queryset(self, qs):
        if self.request.user.is_superuser:
            return qs
        if self.user_can_access_owned_objects_only:
            filters = {self.user_owned_objects_field: self.request.user}
            qs = qs.filter(**filters)
        if self.user_can_access_owned_by_group_objects_only:
            User = get_user_model()
            user_rel_name = User.groups.field.related_query_name()
            qs_key = '%s__%s' % (self.group_owned_objects_field, user_rel_name)
            filters = {qs_key: self.request.user}
            qs = qs.filter(**filters)
        return qs

    def get_urls(self):
        """
        Extends standard admin model urls with the following:

        - ``.../permissions/`` under ``app_mdodel_permissions`` url name (params: object_pk)
        - ``.../permissions/user-manage/<user_id>/`` under ``app_model_permissions_manage_user`` url name (params: object_pk, user_pk)
        - ``.../permissions/group-manage/<group_id>/`` under ``app_model_permissions_manage_group`` url name (params: object_pk, group_pk)

        .. note::
           ``...`` above are standard, instance detail url (i.e.
           ``/admin/flatpages/1/``)

        """
        urls = super(GuardianPlugin, self).get_urls()
        if self.include_object_permissions_urls:
            info = self.model._meta.app_label, get_model_name(self.model)
            myurls = [
                url(r'^(?P<object_pk>.+)/permissions/$',
                    view=self.admin_site.admin_view(
                        self.obj_perms_manage_view),
                    name='%s_%s_permissions' % info),
                url(r'^(?P<object_pk>.+)/permissions/user-manage/(?P<user_id>\-?\d+)/$',
                    view=self.admin_site.admin_view(
                        self.obj_perms_manage_user_view),
                    name='%s_%s_permissions_manage_user' % info),
                url(r'^(?P<object_pk>.+)/permissions/group-manage/(?P<group_id>\-?\d+)/$',
                    view=self.admin_site.admin_view(
                        self.obj_perms_manage_group_view),
                    name='%s_%s_permissions_manage_group' % info),
            ]
            urls = myurls + urls
        return urls

    def get_obj_perms_base_context(self, request, obj):
        """
        Returns context dictionary with common admin and object permissions
        related content. It uses AdminSite.each_context (available in Django >= 1.8,
        making sure all required template vars are in the context.
        """
        if django.VERSION >= (1, 8):
            context = self.admin_site.each_context(request)
        else:
            context = {}
        context.update({
            'adminform': {'model_admin': self},
            'media': self.admin_view.media,
            'object': obj,
            'app_label': self.model._meta.app_label,
            'opts': self.model._meta,
            'original': hasattr(obj, '__unicode__') and obj.__unicode__() or str(obj),
            'has_change_permission': self.admin_view.has_change_permission(request, obj),
            'model_perms': get_perms_for_model(obj),
            'title': _("Object permissions"),
        })
        return context

    def obj_perms_manage_view(self, request, object_pk):
        """
        Main object permissions view. Presents all users and groups with any
        object permissions for the current model *instance*. Users or groups
        without object permissions for related *instance* would **not** be
        shown. In order to add or manage user or group one should use links or
        forms presented within the page.
        """
        if not self.admin_view.has_change_permission(request, None):
            post_url = reverse('xadmin:index', current_app=self.admin_site.name)
            return redirect(post_url)

        from django.contrib.admin.utils import unquote

        obj = get_object_or_404(self.get_queryset(
            request), pk=unquote(object_pk))
        users_perms = OrderedDict(
            sorted(
                get_users_with_perms(obj, attach_perms=True,
                                     with_group_users=False).items(),
                key=lambda user: getattr(
                    user[0], get_user_model().USERNAME_FIELD)
            )
        )

        groups_perms = OrderedDict(
            sorted(
                get_groups_with_perms(obj, attach_perms=True).items(),
                key=lambda group: group[0].name
            )
        )

        if request.method == 'POST' and 'submit_manage_user' in request.POST:
            user_form = self.get_obj_perms_user_select_form(request)(request.POST)
            group_form = self.get_obj_perms_group_select_form(request)(request.POST)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                get_model_name(self.model)
            )
            if user_form.is_valid():
                user_id = user_form.cleaned_data['user'].pk
                url = reverse(
                    '%s:%s_%s_permissions_manage_user' % info,
                    args=[obj.pk, user_id]
                )
                return redirect(url)
        elif request.method == 'POST' and 'submit_manage_group' in request.POST:
            user_form = self.get_obj_perms_user_select_form(request)(request.POST)
            group_form = self.get_obj_perms_group_select_form(request)(request.POST)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                get_model_name(self.model)
            )
            if group_form.is_valid():
                group_id = group_form.cleaned_data['group'].id
                url = reverse(
                    '%s:%s_%s_permissions_manage_group' % info,
                    args=[obj.pk, group_id]
                )
                return redirect(url)
        else:
            user_form = self.get_obj_perms_user_select_form(request)()
            group_form = self.get_obj_perms_group_select_form(request)()

        context = self.get_obj_perms_base_context(request, obj)
        context['users_perms'] = users_perms
        context['groups_perms'] = groups_perms
        context['user_form'] = user_form
        context['group_form'] = group_form

        # https://github.com/django/django/commit/cf1f36bb6eb34fafe6c224003ad585a647f6117b
        request.current_app = self.admin_site.name

        if django.VERSION >= (1, 10):
            return render(request, self.get_obj_perms_manage_template(), context)

        return render_to_response(self.get_obj_perms_manage_template(), context, RequestContext(request))

    def get_obj_perms_manage_template(self):
        """
        Returns main object permissions admin template.  May be overridden if
        need to change it dynamically.
        """
        return self.obj_perms_manage_template

    def obj_perms_manage_user_view(self, request, object_pk, user_id):
        """
        Manages selected users' permissions for current object.
        """
        if not self.admin_view.has_change_permission(request, None):
            post_url = reverse('xadmin:index', current_app=self.admin_site.name)
            return redirect(post_url)

        user = get_object_or_404(get_user_model(), pk=user_id)
        obj = get_object_or_404(self.get_queryset(request), pk=object_pk)
        form_class = self.get_obj_perms_manage_user_form(request)
        form = form_class(user, obj, request.POST or None)

        if request.method == 'POST' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                get_model_name(self.model)
            )
            url = reverse(
                '%s:%s_%s_permissions_manage_user' % info,
                args=[obj.pk, user.pk]
            )
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context['user_obj'] = user
        context['user_perms'] = get_user_perms(user, obj)
        context['form'] = form

        request.current_app = self.admin_site.name

        if django.VERSION >= (1, 10):
            return render(request, self.get_obj_perms_manage_user_template(), context)

        return render_to_response(self.get_obj_perms_manage_user_template(), context, RequestContext(request))

    def get_obj_perms_manage_user_template(self):
        """
        Returns object permissions for user admin template.  May be overridden
        if need to change it dynamically.
        """
        return self.obj_perms_manage_user_template

    def get_obj_perms_user_select_form(self, request):
        """
        Returns form class for selecting a user for permissions management.  By
        default :form:`UserManage` is returned.
        """
        return UserManage

    def get_obj_perms_group_select_form(self, request):
        """
        Returns form class for selecting a group for permissions management.  By
        default :form:`GroupManage` is returned.
        """
        return GroupManage

    def get_obj_perms_manage_user_form(self, request):
        """
        Returns form class for user object permissions management.  By default
        :form:`AdminUserObjectPermissionsForm` is returned.
        """
        return AdminUserObjectPermissionsForm

    def obj_perms_manage_group_view(self, request, object_pk, group_id):
        """
        Manages selected groups' permissions for current object.
        """
        if not self.admin_view.has_change_permission(request, None):
            post_url = reverse('xadmin:index', current_app=self.admin_site.name)
            return redirect(post_url)

        group = get_object_or_404(Group, id=group_id)
        obj = get_object_or_404(self.get_queryset(request), pk=object_pk)
        form_class = self.get_obj_perms_manage_group_form(request)
        form = form_class(group, obj, request.POST or None)

        if request.method == 'POST' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            info = (
                self.admin_site.name,
                self.model._meta.app_label,
                get_model_name(self.model)
            )
            url = reverse(
                '%s:%s_%s_permissions_manage_group' % info,
                args=[obj.pk, group.id]
            )
            return redirect(url)

        context = self.get_obj_perms_base_context(request, obj)
        context['group_obj'] = group
        context['group_perms'] = get_group_perms(group, obj)
        context['form'] = form

        request.current_app = self.admin_site.name

        if django.VERSION >= (1, 10):
            return render(request, self.get_obj_perms_manage_group_template(), context)

        return render_to_response(self.get_obj_perms_manage_group_template(), context, RequestContext(request))

    def get_obj_perms_manage_group_template(self):
        """
        Returns object permissions for group admin template.  May be overridden
        if need to change it dynamically.
        """
        return self.obj_perms_manage_group_template

    def get_obj_perms_manage_group_form(self, request):
        """
        Returns form class for group object permissions management.  By default
        :form:`AdminGroupObjectPermissionsForm` is returned.
        """
        return AdminGroupObjectPermissionsForm
