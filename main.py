import webapp2
import jinja2
import os
import re

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
            autoescape = True)

class Handler(webapp2.RequestHandler):

    def write(self,*a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

class MainPage(Handler):
    
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.render("welcome.html")
    
class Signup(Handler):

        def get(self):
            self.render("signup.html")

        def post(self):

            if self.request.get("user-choice") == "cancel":
                self.redirect("/")
            else:
                username = self.request.get("username")
                email = self.request.get("email")
                password = self.request.get("psw")
                password_rpt = self.request.get("psw-repeat")
                have_error = False

                params = dict(username = username,
                                email = email)

                if not valid_username(username):
                    params['error_username'] = "That's not a valid username."
                    have_error = True

                if not valid_password(password):
                    params['error_password'] = "That wasn't a valid password."
                    have_error = True
                elif password != password_rpt:
                    params['error_verify'] = "Your passwords didn't match."
                    have_error = True

                if not valid_email(email):
                    params['error_email'] = "That's not a valid email."
                    have_error = True

                if have_error:
                    self.render('signup.html', **params)
                else:
                    self.redirect('/thanks?username=' + username)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return email and EMAIL_RE.match(email)

    
class ThanksHandler(Handler):
        def get(self):
            username = self.request.get("username")
            self.render("thanks.html",username = username)
 
app = webapp2.WSGIApplication([('/',MainPage),('/thanks',ThanksHandler),('/signup',Signup)],
                                    debug = True)


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