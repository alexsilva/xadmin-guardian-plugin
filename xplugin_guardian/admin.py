from __future__ import unicode_literals

from collections import OrderedDict

import django
from django.apps import apps
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_permission_codename
from django.db import models
from django.shortcuts import get_object_or_404, redirect, render_to_response, render
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext
from django.utils.translation import ugettext_lazy as _
from django.contrib.admin.utils import unquote
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
from xadmin.views import BaseAdminPlugin, CommAdminView
from xadmin import site


class GuardianPlugin(BaseAdminPlugin):
    """
    Xadmin plugin
    """

    user_can_access_owned_objects_only = False

    user_owned_objects_field = 'user'

    user_can_access_owned_by_group_objects_only = False

    group_owned_objects_field = 'group'

    guarded_model = False

    permission_button_title = _("Object permissions")

    def init_request(self, *args, **kwargs):
        return self.guarded_model

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

    def get_context(self, context):
        if isinstance(getattr(self.admin_view, 'org_obj', None), models.Model):  # is update view
            context.setdefault('guardian', {'button': {
                'title': self.permission_button_title,
                'url': reverse('{0.admin_site.name}:guardian_permissions'.format(self),
                               kwargs=dict(
                                   app_label=self.opts.app_label,
                                   model_name=self.opts.model_name,
                                   object_pk=self.admin_view.org_obj.pk
                               ))
            }})
        return context

    def block_nav_btns(self, context, nodes, *args, **kwargs):
        if isinstance(getattr(self.admin_view, 'org_obj', None), models.Model):  # is update view
            return render_to_string("guardian/includes/permission_manage.html", context=context)


class GuardianCommonView(CommAdminView):
    change_form_template = 'guardian/model/change_form.html'
    obj_perms_manage_template = 'guardian/model/obj_perms_manage.html'
    obj_perms_manage_user_template = 'guardian/model/obj_perms_manage_user.html'
    obj_perms_manage_group_template = 'guardian/model/obj_perms_manage_group.html'

    remove_permissions = []

    def get_obj_perms_base_context(self, request, obj):
        """
        Returns context dictionary with common admin and object permissions related content.
        """
        context = self.get_context()
        context.update({
            'title': _("Object permissions"),
            'base_template': self.base_template,
            'menu_template': self.menu_template,
            'adminform': {'model_admin': self},
            'media': self.media,
            'object': obj,
            'opts': self.opts,
            'app_label': self.app_label,
            'original': hasattr(obj, '__unicode__') and obj.__unicode__() or str(obj),
            'has_change_permission': self.has_change_permission(obj),
            'model_perms': get_perms_for_model(obj),
        })
        return context

    def get_obj_perms_manage_template(self):
        """
        Returns main object permissions admin template.  May be overridden if
        need to change it dynamically.
        """
        return self.obj_perms_manage_template

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

    def has_view_permission(self, obj=None):
        view_codename = get_permission_codename('view', self.opts)
        change_codename = get_permission_codename('change', self.opts)

        return ('view' not in self.remove_permissions) and (
                self.user.has_perm('%s.%s' % (self.app_label, view_codename)) or
                self.user.has_perm('%s.%s' % (self.app_label, change_codename)))

    def has_add_permission(self):
        codename = get_permission_codename('add', self.opts)
        return ('add' not in self.remove_permissions) and self.user.has_perm('%s.%s' % (self.app_label, codename))

    def has_change_permission(self, obj=None):
        codename = get_permission_codename('change', self.opts)
        return ('change' not in self.remove_permissions) and self.user.has_perm('%s.%s' % (self.app_label, codename))

    def has_delete_permission(self, obj=None):
        codename = get_permission_codename('delete', self.opts)
        return ('delete' not in self.remove_permissions) and self.user.has_perm('%s.%s' % (self.app_label, codename))


class GuardianManageView(GuardianCommonView):

    def __init__(self, *args, **kwargs):
        self.app_label = kwargs['app_label']
        self.model_name = kwargs['model_name']
        self.model = self.get_model(self.app_label, self.model_name)
        self.opts = self.model._meta
        super(GuardianManageView, self).__init__(*args, **kwargs)

    @staticmethod
    def get_model(app_label, model_name):
        return apps.get_model(app_label, model_name)

    def get_queryset(self):
        return self.model.objects.all()

    def get(self, request, **kwargs):
        return self.obj_perms_manage_view(request, kwargs['object_pk'])

    def obj_perms_manage_view(self, request, object_pk):
        """
        Main object permissions view. Presents all users and groups with any
        object permissions for the current model *instance*. Users or groups
        without object permissions for related *instance* would **not** be
        shown. In order to add or manage user or group one should use links or
        forms presented within the page.
        """

        current_app = self.admin_site.name

        if not self.has_change_permission():
            post_url = reverse('xadmin:index', current_app=current_app)
            return redirect(post_url)

        obj = get_object_or_404(self.get_queryset(), pk=unquote(object_pk))

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
                current_app,
                self.opts.app_label,
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
                current_app,
                self.opts.app_label,
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
        request.current_app = current_app

        return render(request, self.get_obj_perms_manage_template(), context)


class GuardianManageUserView(GuardianCommonView):

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


class GuardianManageGroupView(GuardianCommonView):
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


# """
# Extends standard admin model urls with the following:
#
# - ``.../permissions/`` under ``app_mdodel_permissions`` url name (params: object_pk)
# - ``.../permissions/user-manage/<user_id>/`` under ``app_model_permissions_manage_user`` url name (params: object_pk, user_pk)
# - ``.../permissions/group-manage/<group_id>/`` under ``app_model_permissions_manage_group`` url name (params: object_pk, group_pk)
#
# .. note::
#    ``...`` above are standard, instance detail url (i.e.
#    ``/admin/flatpages/1/``)

site.register_view(r'^(?P<app_label>.+)/(?P<model_name>.+)/(?P<object_pk>\d+)/permissions/$',
                   GuardianManageView,
                   'guardian_permissions')

site.register_view(r'^(?P<object_pk>.+)/permissions/user-manage/(?P<user_id>\-?\d+)/$',
                   GuardianManageUserView,
                   'guardian_permissions_manage_user')

site.register_view(r'^(?P<object_pk>.+)/permissions/group-manage/(?P<group_id>\-?\d+)/$',
                   GuardianManageUserView,
                   'guardian_permissions_manage_group')
