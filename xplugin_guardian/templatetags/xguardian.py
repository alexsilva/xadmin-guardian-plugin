# coding=utf-8
from django import template

register = template.Library()


@register.simple_tag
def rows_range(counter, total):
    return range(total - counter - 1)
