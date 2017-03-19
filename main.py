# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string

from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# General Purpose Functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

SECRET = "thisissparta"


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure(s):
    return s + "|" + hash_str(s)


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in xrange(length))


def make_pw_hash(username, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(username, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(username, password, salt)


def set_cookie(username):
    cookie = make_secure(username)
    return cookie


def check_cookie(cookie):
    if cookie:
        username = check_secure_val(cookie)
        if username:
            return username


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# The User DataBase
class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()


# The Blog database
class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=False)
    creator = db.StringProperty(required=True)


# The Comments database
class Comment(db.Model):
    comment = db.StringProperty(required=True)
    commenter_name = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class SignUp(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        if not valid_username(username):
            username_error = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            password_error = "That's not a valid password."
            have_error = True

        elif password != verify:
            verify_error = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            email_error = "That's not a valid email"
            have_error = True

        if have_error == True:
            self.render("signup.html", username=username, email=email,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error, email_error=email_error)

        else:
            u = User.all().filter('username =', username).get()
            if u:
                msg = 'That user already exists.'
                self.render('signup.html', username_error=msg)

            else:
                pw_hash = make_pw_hash(username, password)
                u = User(username=username, pw_hash=pw_hash,
                         email=email)
                u.put()
                self.response.headers.add_header("Set-Cookie", "name=%s;Path=/"
                                                 % str(set_cookie(username)))
                self.redirect('/welcome')


class Login(Handler):

    def get(self):
        self.render("login.html")

    def post(self):
        have_error = False
        username = self.request.get("username")
        password = self.request.get("password")
        username_error = ""
        password_error = ""

        if not valid_username(username):
            username_error = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            password_error = "That's not a valid password."
            have_error = True

        if have_error == True:
            self.render("login.html", username=username, password=password,
                        username_error=username_error,
                        password_error=password_error,)

        else:
            u = User.all().filter('username =', username).get()
            if u:
                pw_hash = u.pw_hash
                if valid_pw(username, password, pw_hash):
                    cookie = set_cookie(username)
                    self.response.headers.add_header("Set-Cookie",
                                                     "name=%s; Path=/"
                                                     % str(cookie))
                    self.redirect('/welcome')
                else:
                    error = "User not found."
                    self.render("login.html", username_error=error)
            else:
                error = "User not found."
                self.render("login.html", username_error=error)


class Logout(Handler):

    def get(self):
        self.response.headers.add_header("Set-Cookie", "name=; Path=/")
        self.redirect('/signup')


class Welcome(Handler):

    def get(self):
        cookie = self.request.cookies.get("name")
        username = check_cookie(cookie)
        if username:
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')


# Main blog page Handler
class BlogPage(Handler):

    def get(self):
        blogs = db.GqlQuery("select * from Blog order by created desc")
        comments = db.GqlQuery("select * from Comment order by created asc")
        self.render("blog.html", blogs=blogs, comments=comments)


class NewPost(Handler):

    def get(self):
        cookie = self.request.cookies.get("name")
        if check_cookie(cookie):
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            cookie = self.request.cookies.get("name")
            creator = check_cookie(cookie)
            a = Blog(subject=subject, content=content, likes=0,
                     creator=creator)
            a.put()
            id_this = a.key().id()
            id_this = str(id_this)
            self.redirect("/blog/"+id_this)
        else:
            error = "Enter both the inputs"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


# Permalink Page Handler
class OnePost(Handler):

    def get(self, this_id):
        blogs = db.GqlQuery("select * from Blog")
        subject = ""
        content = ""
        this_id = int(this_id)
        i = Blog.get_by_id(this_id)
        if not i:
            self.error(404)
        else:
            subject = i.subject
            content = i.content
            self.render("OnePost.html", subject=subject, content=content)


# Like Button Handler
class Like(Handler):

    def get(self, this_id):
        cookie = self.request.cookies.get("name")
        if check_cookie(cookie):
            this_id = int(this_id)
            i = Blog.get_by_id(this_id)
            if not i:
                self.error(404)
                return
            if not i.creator == check_cookie(cookie):
                i.likes += 1
                i.put()
                self.redirect("/blog")
            else:
                self.write("!!Cannot Like own Posts!!")

        else:
            self.redirect("/login")


# Delete Button Handler
class Delete(Handler):

    def get(self, this_id):
        cookie = self.request.cookies.get("name")
        if check_cookie(cookie):
            this_id = int(this_id)
            i = Blog.get_by_id(this_id)
            if i.creator == check_cookie(cookie):
                i.delete()
                self.redirect("/blog")
            else:
                self.write("!!Cannot Delete Other's Posts!!")

        else:
            self.redirect("/login")


# Edit Button Handler
class Edit(Handler):

    def get(self, this_id):
        cookie = self.request.cookies.get("name")
        if check_cookie(cookie):
            this_id = int(this_id)
            i = Blog.get_by_id(this_id)
            if not post:
                self.error(404)
                return
            if i.creator == check_cookie(cookie):
                title = i.subject
                content = i.content
                self.render("newpost.html", title=title, content=content)
            else:
                self.write("!!Cannot Edit Other's Posts!!")
        else:
            self.redirect("/login")

    def post(self, this_id):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            this_id = int(this_id)
            i = Blog.get_by_id(this_id)
            i.subject = subject
            i.content = content
            i.put()
            id_this = i.key().id()
            id_this = str(id_this)
            self.redirect("/blog/"+id_this)
        else:
            error = "Enter both the inputs"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

# Comment Add Button Handler


class Comment_add(Handler):

    def post(self, this_id):
        comment = self.request.get("comment")
        if comment:
            this_id = int(this_id)
            i = Blog.get_by_id(this_id)
            if not post:
                self.error(404)
                return
            cookie = self.request.cookies.get("name")
            name = check_cookie(cookie)
            if name:
                a = Comment(
                    comment=comment, commenter_name=name, post_id=this_id)
                a.put()
                self.redirect("/blog")
            else:
                self.redirect("/login")
        else:
            self.write("!!Can not post blank Comments!!")


# Comment Edit Button Handler
class Comment_edit(Handler):

    def get(self, this_id):
        cookie = self.request.cookies.get("name")
        name = check_cookie(cookie)
        if name:
            this_id = int(this_id)
            j = Comment.get_by_id(this_id)
            if j.commenter_name == name:
                self.render("comment_edit.html", comment_text=j.comment, j=j)
            else:
                self.write("!!Can not edit other's comments!!")
        else:
            self.redirect("/login")

    def post(self, this_id):
        comment = self.request.get("comment")
        this_id = int(this_id)
        j = Comment.get_by_id(this_id)
        if not post:
            self.error(404)
            return
        j.comment = comment
        j.put()
        self.redirect("/blog")


# Comment Delete Button Handler
class Comment_del(Handler):

    def get(self, this_id):
        cookie = self.request.cookies.get("name")
        name = check_cookie(cookie)
        if name:
            this_id = int(this_id)
            j = Comment.get_by_id(this_id)
            if not post:
                self.error(404)
                return
            if j.commenter_name == name:
                j.delete()
                self.redirect("/blog")
            else:
                self.write("!!Can not delete other's comments!!")
        else:
            self.redirect("/login")


app = webapp2.WSGIApplication([
    ('/blog', BlogPage),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)', OnePost),
    ('/blog/logout', Logout),
    ('/login', Login),
    ('/signup', SignUp),
    ('/welcome', Welcome),
    ('/logout', Logout),
    ('/like/(\d+)', Like),
    ('/delete/(\d+)', Delete),
    ('/edit/(\d+)', Edit),
    ('/comment_add/(\d+)', Comment_add),
    ('/comment_del/(\d+)', Comment_del),
    ('/comment_edit/(\d+)', Comment_edit)
], debug=True)
