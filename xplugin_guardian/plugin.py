# coding=utf-8
from collections import OrderedDict

from crispy_forms.helper import FormHelper
from django.apps import apps
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.utils import unquote
from django.contrib.auth import get_permission_codename, get_user_model
from django.db import models
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils.translation import ugettext
from django.utils.translation import ugettext_lazy as _
import django.forms as django_forms
from guardian.admin import (
    UserManage,
    GroupManage
)
from guardian.models import Group
from guardian.shortcuts import (
    get_group_perms,
    get_groups_with_perms,
    get_perms_for_model,
    get_user_perms,
    get_users_with_perms
)
from xadmin.plugins.utils import get_context_dict
from xadmin.views import BaseAdminPlugin, CommAdminView, ListAdminView, filter_hook, ModelFormAdminView
from xplugin_guardian import forms

User = get_user_model()


class GuardianPlugin(BaseAdminPlugin):
    """
    Xadmin plugin
    """
    guardian_permissions = False

    guardian_user_owned_objects_field = 'user'
    guardian_group_owned_objects_field = 'group'

    guardian_user_can_access_owned_objects_only = False
    guardian_user_can_access_owned_by_group_objects_only = False

    guardian_permission_button_title = _("Object permissions")

    def init_request(self, *args, **kwargs):
        return self.guardian_permissions

    def queryset(self, qs):
        if self.request.user.is_superuser:
            return qs
        if self.guardian_user_can_access_owned_objects_only:
            filters = {self.guardian_user_owned_objects_field: self.request.user}
            qs = qs.filter(**filters)
        if self.guardian_user_can_access_owned_by_group_objects_only:
            user_rel_name = User.groups.field.related_query_name()
            qs_key = '%s__%s' % (self.guardian_group_owned_objects_field, user_rel_name)
            filters = {qs_key: self.request.user}
            qs = qs.filter(**filters)
        return qs

    def get_context(self, context):
        if isinstance(getattr(self.admin_view, 'org_obj', None), models.Model):  # is update view
            context.setdefault('guardian', {'button': {
                'title': self.guardian_permission_button_title,
                'url': self.get_admin_url("guardian_permissions",
                                        app_label=self.opts.app_label,
                                        model_name=self.opts.model_name,
                                        object_pk=self.admin_view.org_obj.pk)
            }})
        return context

    def block_nav_btns(self, context, nodes, *args, **kwargs):
        context = get_context_dict(context)
        if isinstance(getattr(self.admin_view, 'org_obj', None), models.Model):  # is update view
            return render_to_string("xguardian/includes/permission_manage.html", context=context)


class GuardianCommonView(CommAdminView):
    change_form_template = 'xguardian/model/change_form.html'
    obj_perms_manage_template = 'xguardian/model/obj_perms_manage.html'
    obj_perms_manage_user_template = 'xguardian/model/obj_perms_manage_user.html'
    obj_perms_manage_group_template = 'xguardian/model/obj_perms_manage_group.html'

    remove_permissions = []

    def init_request(self, *args, **kwargs):
        self.app_label = kwargs['app_label']
        self.model_name = kwargs['model_name']
        self.object_pk = kwargs['object_pk']
        self.model = self.get_model(self.app_label, self.model_name)
        self.opts = self.model._meta

    @staticmethod
    def get_model(app_label, model_name):
        return apps.get_model(app_label, model_name)

    def get_queryset(self):
        return self.model.objects.all()

    def get_obj_perms_context(self, obj):
        """
        Returns context dictionary with common admin and object permissions related content.
        """
        context = self.get_context()
        context.update({
            'title': _("Object permissions"),
            'media': self.media,
            'object': obj,
            'opts': self.opts,
            'app_label': self.app_label,
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
        return forms.AdminUserObjectPermissionsForm

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
        return forms.AdminGroupObjectPermissionsForm

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

    def get(self, request, **kwargs):
        return self.obj_perms_manage_view(request, **kwargs)

    def get_media(self):
        media = super(GuardianManageView, self).get_media()
        media += django_forms.Media(js=(
            settings.STATIC_URL + "xguardian/js/perms.manage.form.js",
        ))
        return media

    def obj_perms_manage_view(self, request, **kwargs):
        """
        Main object permissions view. Presents all users and groups with any
        object permissions for the current model *instance*. Users or groups
        without object permissions for related *instance* would **not** be
        shown. In order to add or manage user or group one should use links or
        forms presented within the page.
        """
        if not self.has_change_permission():
            return redirect(self.get_admin_url('index'))

        obj = get_object_or_404(self.get_queryset(), pk=unquote(self.object_pk))

        users_perms = OrderedDict(
            sorted(
                get_users_with_perms(obj, attach_perms=True, with_group_users=False).items(),
                key=lambda user: getattr(user[0], User.USERNAME_FIELD)
            )
        )
        groups_perms = OrderedDict(
            sorted(
                get_groups_with_perms(obj, attach_perms=True).items(),
                key=lambda group: group[0].name
            )
        )

        if self.request_method == 'post' and 'submit_manage_user' in request.POST:
            user_form = self.get_obj_perms_user_select_form(request)(request.POST)
            group_form = self.get_obj_perms_group_select_form(request)

            form = group_form(request.POST)
            if form.is_valid():
                group_form = group_form()

            if user_form.is_valid():
                user_id = user_form.cleaned_data['user'].pk
                url = self.get_admin_url("guardian_permissions_user",
                                        self.app_label,
                                        self.model_name,
                                        obj.pk,
                                        user_id)
                return redirect(url)
        elif self.request_method == 'post' and 'submit_manage_group' in request.POST:
            user_form = self.get_obj_perms_user_select_form(request)
            group_form = self.get_obj_perms_group_select_form(request)(request.POST)

            form = user_form(request.POST)
            if form.is_valid():
                user_form = user_form()

            if group_form.is_valid():
                group_id = group_form.cleaned_data['group'].id
                url = self.get_admin_url("guardian_permissions_group",
                                        self.app_label,
                                        self.model_name,
                                        obj.pk,
                                        group_id)
                return redirect(url)
        else:
            user_form = self.get_obj_perms_user_select_form(request)()
            group_form = self.get_obj_perms_group_select_form(request)()

        helper = FormHelper()
        helper.disable_csrf = True
        helper.form_tag = False
        helper.html5_required = True
        helper.label_class = 'font-weight-bold'
        helper.field_class = 'controls'
        helper.include_media = False
        helper.use_custom_control = False

        user_form.helper = helper
        group_form.helper = helper

        context = self.get_obj_perms_context(obj)

        context['users_perms'] = users_perms
        context['groups_perms'] = groups_perms
        context['user_form'] = user_form
        context['group_form'] = group_form

        return render(request, self.get_obj_perms_manage_template(), context)

    def post(self, request, **kwargs):
        return self.get(request, **kwargs)


class GuardianManageUserView(GuardianCommonView):

    def init_request(self, *args, **kwargs):
        super().init_request(*args, **kwargs)
        self.user_id = kwargs['user_id']

    def get(self, request, **kwargs):
        return self.obj_perms_manage_user_view(request, **kwargs)

    @filter_hook
    def get_media(self):
        media = super(GuardianManageUserView, self).get_media()
        media += self.vendor('xadmin.page.form.js', 'xadmin.form.css')
        return media

    def obj_perms_manage_user_view(self, request, **kwargs):
        """
        Manages selected users' permissions for current object.
        """
        if not self.has_change_permission():
            return redirect(self.get_admin_url('index'))

        user = get_object_or_404(User, pk=self.user_id)
        obj = get_object_or_404(self.get_queryset(), pk=self.object_pk)
        form_class = self.get_obj_perms_manage_user_form(request)
        form = form_class(user, obj, request.POST or None)

        if self.request_method == 'post' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            url = self.get_admin_url("guardian_permissions_user",
                                    self.app_label,
                                    self.model_name,
                                    obj.pk,
                                    self.user_id)
            return redirect(url)

        context = self.get_obj_perms_context(obj)

        context['user_perms'] = get_user_perms(user, obj)
        context['user_obj'] = user
        context['form'] = form

        return render(request, self.get_obj_perms_manage_user_template(),
                      context=context)

    def post(self, request, **kwargs):
        return self.get(request, **kwargs)


class GuardianManageGroupView(GuardianCommonView):

    def init_request(self, *args, **kwargs):
        super().init_request(*args, **kwargs)
        self.group_id = kwargs['group_id']

    def get(self, request, **kwargs):
        return self.obj_perms_manage_group_view(request, **kwargs)

    @filter_hook
    def get_media(self):
        media = super(GuardianManageGroupView, self).get_media()
        media += self.vendor('xadmin.page.form.js', 'xadmin.form.css')
        return media

    def obj_perms_manage_group_view(self, request, **kwargs):
        """
        Manages selected groups' permissions for current object.
        """
        if not self.has_change_permission():
            post_url = self.get_admin_url('index')
            return redirect(post_url)

        group = get_object_or_404(Group, id=self.group_id)

        obj = get_object_or_404(self.get_queryset(), pk=self.object_pk)

        form_class = self.get_obj_perms_manage_group_form(request)
        form = form_class(group, obj, request.POST or None)

        if request.method == 'POST' and form.is_valid():
            form.save_obj_perms()
            msg = ugettext("Permissions saved.")
            messages.success(request, msg)
            url = self.get_admin_url("guardian_permissions_group",
                                    self.app_label,
                                    self.model_name, obj.pk,
                                    self.group_id)
            return redirect(url)

        context = self.get_obj_perms_context(obj)
        context['group_obj'] = group
        context['group_perms'] = get_group_perms(group, obj)
        context['form'] = form

        return render(request, self.get_obj_perms_manage_group_template(), context)

    def post(self, request, **kwargs):
        return self.get(request, **kwargs)


def register_views(admin_site):
    if getattr(admin_site, "__guardian_registered", False):
        return

    regex = r'^(?P<app_label>.+)/(?P<model_name>.+)/(?P<object_pk>\d+)'

    admin_site.register_view(regex + r'/permissions/$',
                             GuardianManageView,
                             'guardian_permissions')

    admin_site.register_view(regex + r'/permissions/user-manage/(?P<user_id>\-?\d+)/$',
                             GuardianManageUserView,
                             'guardian_permissions_user')

    admin_site.register_view(regex + r'/permissions/group-manage/(?P<group_id>\-?\d+)/$',
                             GuardianManageGroupView,
                             'guardian_permissions_group')

    admin_site.register_plugin(GuardianPlugin, ModelFormAdminView)
    admin_site.register_plugin(GuardianPlugin, ListAdminView)
    admin_site.__guardian_registered = True
