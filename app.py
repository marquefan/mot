from flask import Flask, render_template, request, json, session, redirect, url_for, flash, jsonify, abort, send_file
from flask_pymongo import PyMongo
import bcrypt
import bson.binary
import base64
import io
import datetime
import hashlib
import random
from PIL import Image

app = Flask(__name__)
app.config.from_pyfile("config.cfg")


#mongod running on port 27017 on default!
app.config["MONGO_DBNAME"] = "memesoftoday_db"
app.config["MONGO_URI"] = "mongodb://USERNAME:PASSWORD@ds263137.mlab.com:63137/DB_NAME"

mongo = PyMongo(app)

@app.route("/")
def index():
	if "username" in session:
		print(session["username"]+" has logged in")

	return render_template("index.html", img= returnImage())

def returnImage():
	memes_in_db = mongo.db.memes.count()	#count howmany memes
	IMG_FROM_DB = mongo.db.memes.find()[random.randrange(memes_in_db)] #pick random meme

	bytesio_img = io.BytesIO(IMG_FROM_DB["content"]) #convert binary data to BytesIO
	img_buffer = base64.b64encode(bytesio_img.getvalue()).decode("utf-8") #convert it to base64 and decode

	sha = IMG_FROM_DB["sha1"]

	return img_buffer + "$$$" + sha

@app.route("/retrieveImage", methods=["POST"])
def retrieveImage():	#send image(onload and when user made an action)
	target = request.form["target"]
	liked = request.form["liked"]

	user = "$offlineUser"
	if session["username"]:
		user = session["username"]
		

	if liked:
		mongo.db.memes.update_one(
			{"sha1":target},
				{ "$inc": {		#increment likes with 1
					"likes": 1,
					"seen_by": 1}
			},upsert=False)

		mongo.db.memes.update_one(
			{"sha1":target},
				{"$push": {
					"last_seen" : datetime.datetime.utcnow(),
					"last_liked" : datetime.datetime.utcnow(),
					"seen_user" : user}
				}, upsert=False)


		if session["username"]:
			mongo.db.users.update_one(
				{"username": user},
					{"$push": {
						"memes_seen" : target,
						"memes_liked" : target }
					}, upsert=False)


	if not liked:
		mongo.db.memes.update_one(
			{"sha1":target},
				{ "$inc": {		
					"dislikes": 1,
					"seen_by": 1}
			},upsert=False)
		mongo.db.memes.update_one(
			{"sha1":target},
				{"$push": {
					"last_seen" : datetime.datetime.utcnow(),
					"last_disliked" : datetime.datetime.utcnow(),
					"seen_user" : user}
				}, upsert=True)

		if session["username"]:	#if user is logged in
			mongo.db.users.update_one(
				{"username": user},
					{"$push": {
						"memes_seen" : target,
						"memes_disliked" : target }
					}, upsert=True)


	return returnImage()



@app.route("/login", methods=["POST"])
def login():
	users = mongo.db.users

	login_user = users.find_one({"username": request.form["login_username"]})

	if login_user:
		if bcrypt.checkpw(request.form["login_password"].encode("utf-8"), login_user["password"]):
			session["username"] = request.form["login_username"]

			return redirect(url_for("index"))

	flash(u"Wrong username/password combination")
	return redirect(url_for("index"))
	


@app.route("/register", methods=["POST"])
def register():
	if request.method == "POST":
		if len(request.form["register_username"]) >= 3:
			users = mongo.db.users	#mongo collection "users"
			existing_user = users.find_one({"username" : request.form["register_username"]})

			if existing_user is None:
				hashpass = bcrypt.hashpw(request.form["register_password"].encode("utf-8"), bcrypt.gensalt())
				users.insert({
					"username":request.form["register_username"],
					"password":hashpass,
					"memes_seen": [],
					"like_memes": [],
					"disliked_memes": [],
					"registered": datetime.datetime.utcnow(),
					"login_times": []
				})

				session["username"] = request.form["register_username"]
	
				flash(u"registered successfully")
				return redirect(url_for("index"))


			flash(u"That username already exists!")
			return redirect(url_for("index"))

		flash(u"The username must consist of 3 characters or more!")
		return redirect(url_for("index"))

@app.route("/logout")
def logout():
	#destroy session
	session.clear()
	return redirect(url_for("index"))



#meme UPLOAD

"""
mongo.db.memes.ensureIndex({sha1: 1}, {unique: true}) <- auf der mlab seite unter 'index'
bereits erledigt

keine doppelten bilder erlaubt, durch sha1 hash, der mit den Bilder
gespeichert wird, kann erkannt werden, dass es sich um das gleiche Bild
handelt. Wenn die bilder tatsächlich ident sind

mehr: https://www.codeday.top/2017/03/23/9121.html


"""

def save_file(f):
	allowed_formats = set(["jpeg", "jpg", "png", "gif"])
	content = io.BytesIO(f.read())
	try:
		mime = Image.open(content).format.lower()
		if mime not in allowed_formats:
			raise IOError
	except IOError:
		flash(u"Not a supported file/mime format, only: [jpg, png, gif]: error 400")
		return False

	sha1 = hashlib.sha1(content.getvalue()).hexdigest()
	c = dict(
		content=bson.binary.Binary(content.getvalue()),
		mime=mime,
		time=datetime.datetime.utcnow(),
		sha1 = sha1,
		likes=0,
		dislikes=0,
		seen_by=0,
		last_seen=[],
		last_liked=[],
		last_disliked=[],
		seen_user=[]
		)
	try:
		mongo.db.memes.save(c)
		print("saved: ", c["_id"])
	except Exception:
		flash(u"Duplicate Key Error(sha1): identisches Bild bereits vorhanden!")
		return False
	return True

@app.route("/privateUpload", methods=["GET","POST"])
def private_upload():
	if request.method == "GET":		
		if session["username"] == "admin":
			return render_template("private-upload.html")
		return redirect(url_for("index"))
	if session["username"] == "admin":	#notwendig?
		for file in request.files.getlist("uploaded_file"):
		#f = request.files["uploaded_file"]
			if save_file(file):

				flash(u"Upload with success!")
		return redirect(url_for("private_upload"))	



# ERROR HANDLING
@app.errorhandler(404)
def page_not_found(e):
	return "404: Page not found"

"""
@app.errorhandler(405)
def unvalid_request_method(e):
	return redirect(url_for("index"))
"""

if __name__ == "__main__":
	app.secret_key = "asecretkey" # look up later
	app.run(debug=True)
