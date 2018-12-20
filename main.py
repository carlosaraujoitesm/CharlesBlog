
import os
import re

import webapp2
import jinja2
import random
import hmac
import hashlib

from google.appengine.ext import db
from string import letters

#Environment object on application initialization to load templates.
template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
            autoescape = True)

#Use for hash secret for cookies.
secret = 'du.uyX9fE~Tb6.pp&U3D-0smY0,Gqi$^jS34tzu9'

#loads a template from environment
def render_str(template,**params):
        t = jinja_env.get_template(template)
        #To render the template  with some variables
        return t.render(params)

#receives a value and returns a hash to that, using the secret string
def make_secure_val(val):
    return '%s|%s' % (val,hmac.new(secret,val).hexdigest())

#takes one of the up secure vals and checks its integrity
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):

    def write(self,*a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self,template,**params):
        return render_str(template,**params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def set_secure_cookie(self,name,val):
        cookie_val =  make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name,cookie_val))

    def read_secure_cookie(self,name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    #sets the cookie
    def login(self,user):
        self.set_secure_cookie('user-id',str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
            'user-id=; Path=/')
    #checks if the user is logged in or not 
    def initialize(self,*a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid = self.read_secure_cookie('user-id')
        self.user = uid and User.by_id(int(uid))



def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(username,pw,salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username+pw+salt).hexdigest()
    return '%s,%s' % (salt,h) 

def valid_pw(username,password,h):
    salt = h.split(',')[0]
    return h == make_pw_hash(username,password,salt)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
  def get(self):
      self.write("Hello, thank you for visiting my new Blog!")

#ancestor for users
def users_key(group='default'):
    return db.Key.from_path('users',group)

### blog stuff
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)



class Post(db.Model):

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add =True)
    last_modified = db.DateTimeProperty(auto_now =True)
    

    #This is called from the template
    def render(self):
        self.render_text = self.content.replace('\n','<br>')
        return render_str('post.html', p = self)

class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    @classmethod
    def by_id(cls,uid):
        return User.get_by_id(uid,parent=users_key())
    @classmethod
    def by_username(cls,username):
        return User.all().filter('username = ',username).get()

    @classmethod
    def register(cls,username,pw,email):
        pw_hash = make_pw_hash(username,pw)
        return User(parent = users_key(),
                    username=username,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls,username,pw):
        u = cls.by_username(username)
        if u and  valid_pw(username,pw,u.pw_hash):
            return u

   
class Comment(db.Model):


    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add =True)

#This is a page for the entry
class BlogFront(BlogHandler):

    def get(self):
        if self.user:
            posts = db.GqlQuery("select * from Post order by created desc limit 10")
            self.render('front.html',posts=posts)
        else:
            self.redirect('/signin')

    def post(self):
        if self.user:
            key_id = self.request.get('id_or_name')
            self.redirect('/blog/%s/newcomment' % str(key_id))
        else:
            self.redirect('/signin')

#This is the page for a particular post
class PostPage(BlogHandler):

    def get(self,post_id):
        key = db.Key.from_path('Post',int(post_id),parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render('permalink.html',post=post)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/signin')
    def post(self):

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject=subject, content=content)
            p.put()
            self.redirect("/blog/%s" % str(p.key().id()))
        else:
            error = "subject and description, please!"
            self.render('newpost.html',subject=subject,content=content,error=error)


class Signup(BlogHandler):

        def get(self):
            if self.user:
                self.redirect('/blog')
            else:
                self.render('signup.html')

        def post(self):

            if self.request.get('user-choice') == 'cancel':
                self.redirect('/')
            else:
                self.username = self.request.get('username')
                self.email = self.request.get('email')
                self.password = self.request.get('psw')
                self.password_rpt = self.request.get('psw-repeat')
                have_error = False

                params = dict(username = self.username,
                                email = self.email)

                if not valid_username(self.username):
                    params['error_username'] = "That's not a valid username."
                    have_error = True

                if not valid_password(self.password):
                    params['error_password'] = "That wasn't a valid password."
                    have_error = True
                elif self.password != self.password_rpt:
                    params['error_verify'] = "Your passwords didn't match."
                    have_error = True

                if not valid_email(self.email):
                    params['error_email'] = "That's not a valid email."
                    have_error = True

                if have_error:
                    self.render('signup.html', **params)
                else:
                    self.done()

        def done(self,*a,**kw):
                raise NotImplementedError


class Signin(BlogHandler):
    def get(self):

        if self.user:
            self.redirect('/blog')
        else:
            self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username,password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = "Invalid login"
            self.render('login-form.html',error = msg)

class Signout(BlogHandler):
    def get(self):
        if self.user:
            self.logout()
        else:   
            self.redirect('/signin')

class Comments(BlogHandler):
    def get(self,key_id_post,comment_id):
            if self.user:
                address_k = db.Key.from_path('Post',int(key_id_post.split('|')[1]),'Comment',int(comment_id),parent=blog_key())
                comment = db.get(address_k)
                #username = comment.username
                comments = comment.content
                self.render('comments.html',comments=comments)
            else:   
                self.redirect('/signin')

class NewComment(BlogHandler):

    def get(self,key_id):
        if self.user:
            self.render('comment.html')
        else:   
            self.redirect('/signin')

    def post(self,key_id):
    
        content = self.request.get('content')

        #Comment on a post
        if content:
            #Retrieve Post Key  
       
            key = key_id.split('|')[0]
            post_id = key_id.split('|')[1]
            address_k = db.Key.from_path('Post',int(post_id),parent=blog_key())
            p = db.get(address_k)
            c = Comment(parent = p.key() , content=content)
            c.put()
            self.redirect("/blog/%s/comments/%s" % (str(key_id),str(c.key().id())))

        else:
            error = "content, please!"
            self.render('comment.html',content=content,error=error)



def valid_username(username):
    return username and USER_RE.match(username)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
     return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return email and EMAIL_RE.match(email)

class Register(Signup):
    def done(self):
        u = User.by_username(self.username)
        if u:
            msg='That user already exists.'
            self.render('signup.html',error_username=msg)
        else:
            u = User.register(self.username,self.password,self.email)
            u.put()
        self.login(u)
        self.redirect('/welcome')

class Welcome(BlogHandler):
        def get(self):
            if self.user:
                self.render('welcome.html',username = self.user.username)
            else:
                self.redirect('/signin')

app = webapp2.WSGIApplication([('/',MainPage),
                               ('/signup',Register),
                               ('/welcome',Welcome),
                               ('/blog/?',BlogFront),
                               ('/blog/([0-9]+)',PostPage),
                               ('/blog/newpost',NewPost),
                               ('/blog/(.*?)/newcomment',NewComment),
                               ('/blog/(.*?)/comments/([0-9]+)',Comments),
                               ('/signin',Signin),
                               ('/signout',Signout),
                               ],debug = True)










### Birthday validation stuff
"""
   user_month = self.request.get("month")
        user_day   = self.request.get("day")
        user_year  = self.request.get("year")

        valid_user_month = self.valid_month(user_month)
        valid_user_day   = self.valid_day(user_day)
        valid_user_year  = self.valid_year(user_year)


        if not(valid_user_month and valid_user_day and valid_user_year):
            self.render("signup.html",month=user_month, day=user_day,year=user_year)
        else:
            self.redirect("/thanks")


    def valid_month(self,month):
        if month:
            short_month = month[:3]
            return months_dict.get(short_month)
    
    def valid_day(self,day):
        if day and day.isdigit():
            day = int(day)
            if(day > 0 and day <=31):
                return day

    def valid_year(self,year):
        if year and year.isdigit():
            year = int(year)
            if(year > 1900 and year < 2019):
                return year

months = ["January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December"]

months_dict = dict( (m[:3].lower(),m) for m in months)




"""