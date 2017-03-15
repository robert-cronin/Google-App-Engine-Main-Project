# Title: Multi-User Blog
# Description:
A simple blog that allows users to register, signin, and create/delete/edit blog posts.

# Files:
/static/main.css
  Styling css file

/templates/base.html
  Main template where all jinja templates feed into
/templates/deletepost.html
  Page for deleting specific post
/templates/editpost.html
  Page for editing specific post
/templates/front.html
  Front page for showing all posts
/templates/login-form.html
  Page for logging in as a specific user
/templates/newpost.html
  Page for creating new post
/templates/permalink.html
  Page dedicated to specific post
/templates/post.html
  Page dedicated to specific post
/templates/signup-form.html
  Page for registering new user

app.yaml
index.yaml
  Configuration files

lifeofmomentum.py
  Contains the main code to create the application, built using python and Google App Engine.

# How to run project:
Project is run using google app engine for specific project id. Please visit http://udacity-main-project.appspot.com/lom for the deployed project.
