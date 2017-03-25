import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'lifeofmomentum'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def user_owns_post(self, post):
        return self.user.key().id() == post.user_id

    def user_owns_comment(self, comment):
        return self.user.key().id() == comment.user_id


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Create Post database table

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_name = db.StringProperty(required = True)
    user_id = db.IntegerProperty(required = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

# Create Comment database table

class Comment(db.Model):
    user_name = db.StringProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    post_id = db.IntegerProperty(required = True)

class PostLike(db.Model):
    post_id = db.IntegerProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    user_name = db.StringProperty(required = True)

class CommentLike(db.Model):
    post_id = db.IntegerProperty(required = True)
    comment_id = db.IntegerProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    user_name = db.StringProperty(required = True)



class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        return self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)
        # commentkey = db.Key.from_path('Comment', int(post_id), parent=blog_key())
        # comments = db.get(commentkey)
        comments = Comment.all()

        if not post:
            self.error(404)
            return

        return self.render("permalink.html", post = post, comments = comments)

class NewComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            return self.render("newcomment.html")
        else:
            return self.redirect("/lom/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect("/lom/login")

        content = self.request.get('content')
        user_name = self.user.name
        user_id = self.user.key().id()

        if content:
            c = Comment(post_id = int(post_id), parent = blog_key(), content = content, user_name = user_name, user_id = user_id)
            c.put()
            return self.redirect('/lom/%s'%post_id)
        else:
            error = "Please provide both a title and content"
            return self.render("newcomment.html", content=content, error=error)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            return self.render("newpost.html")
        else:
            return self.redirect("/lom/login")

    def post(self):
        if not self.user:
            return self.redirect('/lom')

        subject = self.request.get('subject')
        content = self.request.get('content')
        user_name = self.user.name
        user_id = self.user.key().id()

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user_name = user_name, user_id = user_id)
            p.put()
            return self.redirect('/lom/%s' % str(p.key().id()))
        else:
            error = "Please provide both a title and content"
            return self.render("newpost.html", subject=subject, content=content, error=error)

# Define Edit and Delete post handlers

class EditComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        # Check if comment_id exists:
        if not comment:
            return self.error(404)
        # Check is valid user first:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_comment(comment):
            return self.redirect('/lom/login')
        # Else continue to post request:
        else:
            return self.render('editcomment.html', comment=comment)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        # Double check valid user:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_comment(comment):
            return self.redirect('/lom/login')
        # Else continue to edit post function:
        content = self.request.get('content')
        if content:
            update = Comment.get_by_id(int(comment_id), parent=blog_key())
            update.content = content
            update.put()
            return self.redirect('/lom/%s' % str(update.post_id))

class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # Check if post exists:
        if not post:
            return self.error(404)
        # Check is valid user first:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_post(post):
            return self.redirect('/lom/login')
        # Else continue to post request:
        else:
            return self.render('editpost.html', post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # Double check valid user:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_post(post):
            return self.redirect('/lom/login')
        # Else continue to edit post function:
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            update = Post.get_by_id(int(post_id), parent=blog_key())
            update.subject = subject
            update.content = content
            update.put()
            return self.redirect('/lom/%s' % str(update.key().id()))

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        # Check if post exists:
        if not comment:
            return self.error(404)
        # Double check valid user:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_comment(comment):
            return self.redirect('/lom/login')
        # Else continue to post request:
        else:
            return self.render("deletecomment.html", comment = comment)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        # Double check valid user:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_comment(comment):
            return self.redirect('/lom/login')
        # Else continue to delete post function:
        else:
            comment.delete()
            return self.redirect('/lom/%s' % str(comment.post_id))

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # Check if post exists:
        if not post:
            return self.error(404)
        # Double check valid user:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_post(post):
            return self.redirect('/lom/login')
        # Else continue to post request:
        else:
            return self.render("deletepost.html", post = post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # Double check valid user:
        if not self.user:
            return self.redirect('/lom/login')
        if not self.user_owns_post(post):
            return self.redirect('/lom/login')
        # Else continue to delete post function:
        else:
            post.delete()
            return self.redirect("/lom")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            return self.render('signup-form.html', **params)
        else:
            return self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/lom')

class Login(BlogHandler):
    def get(self):
        return self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/lom')
        else:
            msg = 'Invalid login'
            return self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/lom')

app = webapp2.WSGIApplication([('/lom/?', BlogFront),
                               ('/lom/([0-9]+)', PostPage),
                               ('/lom/newpost', NewPost),
                               ('/lom/([0-9]+)/newcomment', NewComment),
                               ('/lom/signup', Register),
                               ('/lom/login', Login),
                               ('/lom/logout', Logout),
                               ('/lom/deletepost/([0-9]+)', DeletePost),
                               ('/lom/deletecomment/([0-9]+)', DeleteComment),
                               ('/lom/editpost/([0-9]+)', EditPost),
                               ('/lom/editcomment/([0-9]+)', EditComment)],
                               debug=True)
