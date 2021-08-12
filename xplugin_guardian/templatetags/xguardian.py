# coding=utf-8
from django import template

register = template.Library()


@register.simple_tag
def rows_range(counter, total):
	return range(total - counter - 1)


@register.simple_tag(takes_context=True)
def permission_edit_url(context, obj):
	admin_view = context['admin_view']
	opts = obj._meta
	url = admin_view.get_admin_url(
		f"guardian_permissions_{opts.model_name}",
		context['app_label'],
		context['opts'].model_name,
		context['object'].pk,
		obj.pk
	)
	return url
