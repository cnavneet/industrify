from flask import Flask, render_template, request, redirect, url_for, flash, session, escape, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Products, Hits

import re
import random
import hashlib
import hmac
from string import letters

app = Flask(__name__)

engine = create_engine('sqlite:///database.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

secret='gduiwdhe28ey3812983uio12rhe3900-`--'
cat = ""

def make_secure_val(val):
	return '%s|%s'%(val,hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val=secure_val.split('|')[0]
	if secure_val==make_secure_val(val):
		return val

def set_secure_cookie(name,val):
	resp=make_response(redirect(url_for('profile')))
	resp.set_cookie(name,val)

def read_secure_cookie(name):
	uid=request.cookies.get(name)
	return uid

def login(user):
	set_secure_cookie('user_id',user)

@app.route('/logout')
def logout():
	resp=make_response(redirect('/'))
	resp.set_cookie('user_id',"")
	return resp

def initialize(*a,**kw):
	initialize(*a,**kw)
	uid=read_secure_cookie('user_id')
	q=session.query(Brand).filter_by(id=uid).one()
	user=uid
	if user and q:
		return user

def make_salt(length=5):
	return ''.join(random.choice(letters) for x in range(length))

def make_pw_hash(name,pw,salt=None):
	if not salt:
		salt=make_salt()
	h=hashlib.sha256((name+pw+salt).encode()).hexdigest()
	return '%s,%s'%(salt,h)

def valid_pw(name,password,h):
	salt=h.split(',')[0]
	return h==make_pw_hash(name,password,salt)

USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE=re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE=re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

@app.route('/', methods = ['POST', 'GET'])
def signin():
    if request.cookies.get('user_id'):
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        u = session.query(User).filter_by(username = username).all()
        if u and valid_pw(username, password, u[0].password):
            resp = make_response(redirect('profile'))
            resp.set_cookie('user_id', str(u[0].id))
            return resp
        msg = "Invalid Login!!"
        return render_template('welcome.html', msg = msg)
    return render_template('welcome.html')

@app.route('/signup', methods = ['POST', 'GET'])
def signup():
    if request.cookies.get('user_id'):
        return redirect(url_for('profile'))
    if request.method == 'POST':
        have_error = False
        username = request.form['username']
        password = request.form['password']
        verify = request.form['verify']

        params = dict(username = username)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username!!"
            have_error = True
        if not valid_password(password):
            params['error_password'] = "That's not a valid password!!"
            have_error = True
        elif password != verify:
            params['error_verify']="Your passwords didn't match!!"
            have_error = True
        
        u = session.query(User).filter_by(username = username).all()

        if u:
            params['error_user']="User with this username already exists!!"
            have_error = True

        if have_error:
            return render_template('signup.html', **params)
        else:
            pw = make_pw_hash(username, password)
            newUser = User(username = username, password = pw)
            session.add(newUser)
            session.commit()

            id = session.query(User).filter_by(username = username, password = pw).one()

            resp = make_response(redirect('profile'))
            resp.set_cookie('user_id', str(id.id))
            return resp

    return render_template('signup.html')

@app.route('/profile', methods = ['GET', 'POST'])
def profile():
    cat = ""
    if request.method == 'POST':
        cate = request.form['category']
        cat = cate
    if request.cookies.get('user_id'):
        user_id = int(request.cookies.get('user_id'))
        if cat != "":
            products = session.query(Products).filter_by(category = cat).order_by(Products.uhits.desc()).all()
        else:
            products = session.query(Products).order_by(Products.uhits.desc()).all()
        user = session.query(User).filter_by(id = user_id).one()
        return render_template('profile.html', products = products, user = user)
    else:
        return redirect(url_for('signin'))

@app.route('/admin', methods = ['GET', 'POST'])
def admin():
    user = session.query(User).all()
    products = session.query(Products).all()
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        thits = 0
        uhits = 0

        newProduct = Products(name = name, category = category, thits = thits, uhits = uhits)
        session.add(newProduct)
        session.commit()

        flash("Successfully added "+name+" into "+category+" category!")
        return redirect(url_for('admin'))

    return render_template('admin.html', user = user, products = products)

@app.route('/profile/<int:pid>/<int:uid>/modify')
def modify(pid, uid):
    if not request.cookies.get('user_id'):
        return redirect(url_for('signin'))
    u = session.query(Hits).filter_by(pid = pid, uid = uid).all()
    if not u:
        newHits = Hits(pid= pid, uid = uid)
        session.add(newHits)
        session.commit()
        product = session.query(Products).filter_by(id = pid).one()
        product.thits = product.thits + 1
        product.uhits = product.uhits + 1
        session.add(product)
        session.commit()
        return redirect(url_for('profile'))

    product = session.query(Products).filter_by(id = pid).one()
    product.thits = product.thits + 1
    session.add(product)
    session.commit()
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)