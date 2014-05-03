#coding: utf-8

import datetime
from google.appengine.ext.webapp import template
register = template.create_template_register()


def creatime(value, h=0):
    return (value+datetime.timedelta(hours=int(h))).strftime('%Y-%m-%d %H:%M:%S') if value else ""
register.filter(creatime)

def creatday(value, h=0):
    return (value+datetime.timedelta(hours=int(h))).strftime('%Y-%m-%d') if value else ""
register.filter(creatday)