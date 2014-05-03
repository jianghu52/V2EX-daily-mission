#coding: utf-8

import logging
import webapp2
import os
import re
import json
import datetime
import urllib
import urllib2
import StringIO
import gzip
from cookielib import Cookie
from google.appengine.ext.webapp import template
from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.api import taskqueue


# TZONE_OFFSET_HOURS_V2EX = 8    #v2ex的时间与gae时间差
TZONE_OFFSET_HOURS_SITE = 8    #本站显示时间与gae时间差


TEMPLATE_MAIN = os.path.join(os.path.dirname(__file__), 'main.html')
TEMPLATE_LOG  = os.path.join(os.path.dirname(__file__), 'log.json')
TEMPLATE_TR   = os.path.join(os.path.dirname(__file__), 'tr.html')
PAGE_404 = '<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1>The resource could not be found.<br /><br /></body></html>'

IS_DEBUG = False

class Accounts(db.Model):
    v_user    = db.StringProperty()                         #V2EX用户
    v_cookie  = db.TextProperty()                           #V2EX Cookie，用于登录签到
    author    = db.UserProperty()                           #账户的添加人
    date_add  = db.DateTimeProperty()                       #账户添加日期
    coin_got  = db.FloatProperty(default=0.0)               #自动签到获得金币数
    coin_count= db.IntegerProperty(default=0)               #成功自动签到次数
    coin_all  = db.FloatProperty(default=0.0)               #金币总数
    coin_last = db.FloatProperty(default=0.0)               #最后一次签到所得
    date_last = db.DateTimeProperty()                       #最后一次签到时间
    days_last = db.IntegerProperty(default=0)               #签到持续天数
    days_max  = db.IntegerProperty(default=0)               #最高持续天数
    enabled   = db.BooleanProperty(default=True)            #是否使用签到功能


class AppLog(db.Model):
    v_user    = db.ReferenceProperty(Accounts, collection_name='logs') #v2ex账户
    date      = db.DateTimeProperty()                       #日志日期
    coin      = db.FloatProperty(default=0.0)               #获得的金币数目
    days      = db.IntegerProperty(default=0)               #当前的连续天数
    memo      = db.StringProperty(default="")               #说明，为v2ex的获得的金币说明
    result    = db.BooleanProperty(default=True)            #操作是否成功

# memcaches = {
#     v_user : {
#         'waiting' : True,
#         'success' : False,

#     }
# }
def curl(url, data=None, method='GET', referer=None, header=None, cookier=None, opener=None):
    _header = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': 'Opera/9.80 (Windows NT 6.1; U; http://v2ex-daily.appspot.com; zh-cn) Presto/2.10.229 Version/11.60',
        'Referer' : 'http://www.v2ex.com/',
        'Accept-Language': 'zh-cn,zh,en',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Charset':'GB2312,utf-8',
        'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
        'Connection':'Keep-Alive, TE'
    }

    _cookie = urllib2.HTTPCookieProcessor() if not cookier else cookier
    _opener = urllib2.build_opener(_cookie) if not opener else opener

    if referer:
        _header.update({
            'Referer':referer
        })
    if header and type(header) is dict:
        _header.update(header)

    if method.upper() == 'POST':
        if not data: data = {}
        data = urllib.urlencode(data).encode('utf-8')
        request = urllib2.Request(url= url,
                                  headers= _header,
                                  data= data)
    else:
        if data:
            data = urllib.urlencode(data).encode('utf-8')
            request = urllib2.Request(url ='%s?%s' % (url, data),
                                      headers= _header)
        else:
            request = urllib2.Request(url =url,
                                      headers= _header)
    try:
        response = _opener.open(request, timeout= 60)
        x= response.read()
    except:
        return False

    if 'gzip' in str(response.info().get('Content-Encoding')).lower():
        buf = StringIO.StringIO(buf = x)
        f = gzip.GzipFile(fileobj= buf)
        x = f.read()
    try:
        ret = x.decode('utf-8')
    except UnicodeDecodeError:
        ret = x
    response.close()
    return ret


def getLocalNowTime(hours=TZONE_OFFSET_HOURS_SITE):
    return datetime.datetime.utcnow()+datetime.timedelta(hours=hours)


def addAppLog(v_user, coin=0, days=0, memo=None, result=True):
    log=AppLog()
    if type(v_user) == str or type(v_user) == unicode:
        log.v_user=Accounts.all().filter('v_user = ', v_user).get()
    else:
        log.v_user=v_user
    log.date=getLocalNowTime()
    log.coin=float(coin)
    log.days=int(days)
    log.memo=memo
    log.result=result
    log.put()
    return


class TaskCronStartHandler(webapp2.RequestHandler):
    def get(self):
        v_users = Accounts.all().filter('enabled = ', True)
        if v_users.count():
            for u in v_users:
                taskqueue.add(url='/runtask', params={'user': u.v_user,'cookie':u.v_cookie})
        return


class UserStartCronHandler(webapp2.RequestHandler):
    def get(self):
        user = users.get_current_user()
        if not user:
            self.error(404)
            return
        v_users = Accounts.all().filter('author = ', user).filter('enabled = ', True)
        if v_users.count():
            for u in v_users:
                #if u.author==user:
                taskqueue.add(url='/runtask', params={'user': u.v_user,'cookie':u.v_cookie})
        self.redirect(uri='/', code=301)
        return


class TaskQueueWalker(webapp2.RequestHandler):
    # /mission/daily页面，领取铜币按钮
    SIGN_OK = 'icon-ok-sign'
    URL_SIGN = 'http://www.v2ex.com/mission/daily'
    URL_BALANCE = 'http://www.v2ex.com/balance'

    reRedeem = re.compile(ur'(/mission/daily/redeem\?once=\d+)')
    
    # /balance页面，匹配两次，取前两次的记录，第二次为连续登录奖励（判断）
    # [0][0]：日期，[0][1]：类型，[0][2]：数额，[0][3]：余额，[0][4]：描述
    reRecord = re.compile(  ur'class="gray">(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})</small>.+?' +\
                            ur'class="d">(.+?)</td>.+?' +\
                            ur'<strong>([\d\.]+)</strong>.+?' +\
                            ur'right;">([\d\.]+)</td>.+?'+\
                            ur'class="gray">(.+?)</span></td>', re.DOTALL)

    # /mission/daily页面 连续天数 [1]：连续天数
    reStatus = re.compile(ur'</div>[\n\s\t]+<div\sclass="cell">(.+?)(\d+)(.+?)</div>')

    def importCookie(self, v_cookie):
        a_cookies=json.loads(v_cookie)
        for c in a_cookies:
            self.c_cookie.cookiejar.set_cookie(
                Cookie(
                    version=None, name=c['name'], value=c['value'],
                    port=None, port_specified=False, 
                    domain=c['domain'], domain_specified=True, domain_initial_dot=False,
                    path=c['path'], path_specified=True, 
                    secure=False, 
                    expires=c['expires'],
                    discard=False, 
                    comment=None, comment_url=None, 
                    rest=None, rfc2109=False
                )
            )

    def redeem(self, html):
        # if url=='':
        pass

    def get(self):
        self.error(404)
        self.response.out.write(PAGE_404)
        return

    def post(self):
        v_user = self.request.get('user')
        v_cookie = self.request.get('cookie')

        if not v_user and not v_cookie:
            return
        self.c_cookie = urllib2.HTTPCookieProcessor()
        self.importCookie(v_cookie)
        self.c_opener = urllib2.build_opener(self.c_cookie)

        html=curl(self.URL_SIGN, referer='http://www.v2ex.com', cookier=self.c_cookie, opener=self.c_opener)
        if not html:
            #some thing wrong
            addAppLog(
                v_user, 0, 0, u'错误：无法读取页面：/mission/daily！', False
            )
            return
        ret_redeem = self.reRedeem.search(html)
        if not ret_redeem:
            if self.SIGN_OK in html:
                #signed
                addAppLog(
                    v_user, 0, 0, u'信息：已登录。', True
                )
                pass
        else:
            url_redeem = ret_redeem.group()
            html=curl('http://www.v2ex.com%s' % url_redeem, referer=self.URL_SIGN, cookier=self.c_cookie, opener=self.c_opener)
            if not html:
                #err
                #self.response.out.write('err: open redeem url failed')
                addAppLog(
                    v_user, 0, 0, u'错误：无法打开领铜币链接： %s ！' % url_redeem, False
                )
                return

        #读取连续天数
        ret_status = self.reStatus.search(html)
        if not ret_status:
            #no status
            addAppLog(
                v_user, 0, 0, u'提示：没有连续登录天数的信息，可能登录失败。', True
            )
            pass
        else:
            #update status TODO
            # addAppLog(
            #     v_user, 0, 0, 'Warn: Status change to xx.', False
            # )
            pass

        if ret_status:
            days=int(ret_status.group(2))
            usr = Accounts.all().filter('v_user = ', v_user).get()
            if usr.days_last==days:
                #已经更新了balance数据
                addAppLog(
                    v_user, 0, 0, u'信息：已经领过今天的铜币。', True
                )
                return

        html=curl(self.URL_BALANCE, referer=self.URL_SIGN, cookier=self.c_cookie, opener=self.c_opener)
        if not html:
            #err to read banlance
            addAppLog(
                v_user, 0, 0, u'错误: 无法读取页面：/banlance。', False
            )
            return

        ret_balance = self.reRecord.search(html)
        if ret_balance:
            #查找第二条balance TODO,check if .group(2) can doing this
            ret_balance2 = self.reRecord.search(html, ret_balance.start()+1)
        else:
            ret_balance2 = None

        b = []
        if ret_balance:
            b.append({
                'date'    : datetime.datetime.strptime(ret_balance.group(1), '%Y-%m-%d %H:%M:%S'),
                'type'    : ret_balance.group(2),
                'coin'    : float(ret_balance.group(3)),
                'balbace' : float(ret_balance.group(4)),
                'memo'    : ret_balance.group(5)
            })
        if ret_balance2:
            if ret_balance.group(1)==ret_balance2.group(1):
                #连续登陆奖励
                b.append({
                    'date'    : datetime.datetime.strptime(ret_balance2.group(1), '%Y-%m-%d %H:%M:%S'),
                    'type'    : ret_balance2.group(2),
                    'coin'    : float(ret_balance2.group(3)),
                    'balbace' : float(ret_balance2.group(4)),
                    'memo'    : ret_balance2.group(5)
                })
        if len(b):
            #更新用户
            usr = Accounts.all().filter('v_user = ', v_user).get()
            usr.coin_got+=b[0]['coin']
            usr.coin_all=b[0]['balbace']
            usr.coin_last=b[0]['coin']
            usr.date_last=b[0]['date']
            usr.coin_count+=1
            if ret_status:
                usr.days_last=int(ret_status.group(2))
                usr.days_max=max(usr.days_max, usr.days_last)
            if len(b)==2:
                usr.coin_got+=b[1]['coin']
                usr.coin_last+=b[1]['coin']
            usr.put()

            for x in b:
                #添加日志
                addAppLog(
                    usr, x['coin'], usr.days_last, x['memo']
                )
        return


class MainPageHandler(webapp2.RequestHandler):
    c_cookie = urllib2.HTTPCookieProcessor()
    c_opener = urllib2.build_opener(c_cookie)
    URL_SIGNIN = 'http://www.v2ex.com/signin'
    reSigninCode = re.compile(ur'<input\stype="hidden"\svalue="(\d+)"\sname="once"')

    def exportCookie(self):
        ret = []
        for c in self.c_cookie.cookiejar:
            ret.append({
                'name':c.name,
                'value':c.value,
                'domain':c.domain,
                'path':c.path,
                'expires':c.expires
            })
        return json.dumps(ret)
    
    def signin(self, username, passcode):
        if IS_DEBUG:
            return True

        html = curl(url=self.URL_SIGNIN, referer='http://www.v2ex.com', cookier=self.c_cookie, opener=self.c_opener)
        if not html:
            self.response.out.write(u'无法打开登录页面。')
            return False
        ret_signincode = self.reSigninCode.search(html)
        if not ret_signincode:
            self.response.out.write(u'暂时不可用，找不到验证码。')
            return False
        s_code = int(ret_signincode.group(1))
        if s_code==0:
            self.response.out.write(u'验证码识别错误。')
            return False
        data = {
            'u': username,
            'p': passcode,
            'once': s_code,
            'next':'/'
        }
        passcode='awegawgeawegawefawefawg'
        html = curl(url=self.URL_SIGNIN, method='POST', data=data, referer=self.URL_SIGNIN, cookier=self.c_cookie, opener=self.c_opener)
        if not html:
            self.response.out.write(u'无法读取登录页面')
            return False
        if '<a href="/member/%s" class="top">%s</a>' % (username, username) not in html:
            self.response.out.write(u'登录失败')
            return False
        return True

    def get(self):
        user = users.get_current_user()
        if not user:
            self.response.out.write('<html><body><a href="%s">Signin with Google OpenID</a></body></html>' % users.create_login_url('/'))
            return
        usrs = Accounts.all().filter('author = ', user).order('date_add')
        template_values = {
            'LoginAs'  : user.nickname(),
            'LogoutUrl': users.create_logout_url('/'),
            'Users'    : usrs,
            'empty'    : usrs.count()==0
        }
        self.response.out.write(template.render(TEMPLATE_MAIN, template_values))
        return

    def post(self):
        #模拟登录并保存cookies
        action = self.request.get('action').lower()

        if action=='login':
            uname = self.request.get('u')
            pword = self.request.get('p')
            if len(uname.strip())==0 or len(pword.strip())==0:
                self.response.out.write(u'用户名或密码不能为空。')
                return
            ret= self.signin(uname, pword)
            pword='abcccccdaeawgawegawe'
            if ret:
                v_cookie=unicode(self.exportCookie())
                if Accounts.all().filter('v_user = ', uname).count(1):
                    #修改cookie
                    #验证已保存的账户和正在改信息的账户是不是同一个，不是的话就拒绝修改
                    usr=Accounts.all().filter('v_user = ', uname).get()
                    if usr.author != users.get_current_user():
                        self.response.out.write(u'该用户已经添加！')
                        addAppLog(
                            usr, 0, 0, u'警告：%s正在试图添加你的V2EX账户, 操作已被取消。' % users.get_current_user(), False
                        )
                        return
                    usr.v_cookie=v_cookie
                    usr.put()
                else:
                    #添加账户
                    usr=Accounts(key_name=uname)
                    usr.date_add = getLocalNowTime()
                    usr.v_user=uname
                    usr.v_cookie=v_cookie
                    usr.author = users.get_current_user()
                    usr.put()
                    addAppLog(
                        usr, 0, 0, u'信息：添加用户。', True
                    )
            else:
                #self.response.out.write('Failed')
                return
        if action in ['enable','delete','log']:
            uname=self.request.get('u')
            usr=Accounts.all().filter('author = ', users.get_current_user()).filter('v_user = ', uname)
            if usr.count(1):
                usr=usr.get()
                if action=='enable':
                    usr.enabled=not usr.enabled
                    if usr.enabled==False:
                        usr.v_cookie=None
                    usr.put()
                    addAppLog(
                        usr, 0, 0, u'信息：变更用户状态。%s' % u'激活自动签到' if usr.enabled else u'取消自动签到' , True
                    )
                elif action=='delete':
                    addAppLog(
                        usr, 0, 0, u'信息：删除用户。账户日志也应该删除。', True
                    )
                    db.delete(usr.logs)
                    db.delete(usr)
                    
                elif action=='log':
                    template_values = {
                        'data' : template.render(TEMPLATE_TR, {'logs': usr.logs.order('date')}),
                        'prev' : False,
                        'next' : False,
                        'page' : 1
                    }
                    self.response.out.write(template.render(TEMPLATE_LOG, template_values))
                    return
            else:
                MSG_ENABLE_OK = 'V2EX用户 %s 不属于你的账户。'
                MSG_ENABLE_ER = '该用户不存在。'

                try:
                    self.response.out.write(MSG_ENABLE_OK % uname)
                except:
                    self.response.out.write(MSG_ENABLE_ER)

                #提示用户其他人正在试图修改他的v2ex账户
                addAppLog(
                    usr.get(), 0, 0, u'警告：%s正在试图查看你的日志或修改你的V2EX账户, 操作已被取消。' % users.get_current_user(), False
                )
                return

        self.response.out.write('OK')
        return


app = webapp2.WSGIApplication(
    [
        ('/daily', TaskCronStartHandler),
        ('/manual', UserStartCronHandler),
        ('/runtask', TaskQueueWalker),
        ('/', MainPageHandler)
    ], debug=IS_DEBUG
)