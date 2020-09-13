import os
from flask import Flask, jsonify, request, json
import pymongo
from bson.objectid import ObjectId
from datetime import datetime
from flask_cors import CORS, cross_origin
#import ssl
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'secret'

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

mongoPath = os.environ['MONGO_BASE_URL']
portNumber = os.environ['PORT']

def _build_cors_prelight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "*")
    return response

def _corsify_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

@app.route('/api/auth/signup', methods=['POST', 'OPTIONS'])
def register():
    if request.method == "OPTIONS": # CORS preflight
    	return _build_cors_prelight_response()
    elif request.method == "POST":
    	client = pymongo.MongoClient(mongoPath)
    	db = client.get_database('myDB')
    	records = db.users
	
    	username = request.get_json()['username']
    	email = request.get_json()['email']
    	password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    	created = datetime.utcnow()
    	user_id = records.insert_one({
		'username' : username, 
		'email' : email, 
		'password' : password, 
		'created' : created, 
		})
    	result = {'email' : email + ' registered'}
    	return _corsify_actual_response(jsonify({'result' : result}))

@app.route('/api/total', methods=['POST'])
def total():
    client = pymongo.MongoClient(mongoPath)
    db = client.get_database('myDB')
    records = db.total

    username = request.get_json()['username']
    storyname = request.get_json()['storyname']
    db.total.update({ "username": username,"storyname":storyname }, 
    { "username": username,"storyname":storyname },
     upsert=True )
    db.curr.update({ "username": username,"storyname":storyname }, 
    { "username": username,"storyname":storyname },
     upsert=True )
    number=records.count_documents({"storyname":storyname})
    numberone=db.curr.count_documents({"storyname":storyname})
    return jsonify({'total' : number,'curr':numberone})

@app.route('/api/counting', methods=['POST'])
def counting():
    client = pymongo.MongoClient(mongoPath)
    db = client.get_database('myDB')
    records = db.total
    storyname = request.get_json()['storyname']
    number=records.count_documents({"storyname":storyname})
    numberone=db.curr.count_documents({"storyname":storyname})
    return jsonify({'total' : number,'curr':numberone})

@app.route('/api/curr', methods=['POST'])
def currdel():
    client = pymongo.MongoClient(mongoPath)
    db = client.get_database('myDB')
    records = db.curr

    username = request.get_json()['username']
    storyname = request.get_json()['storyname']
    records.delete_one({ "username": username,"storyname":storyname })
    
    return jsonify({'result' : "done"})
	

@app.route('/api/auth/signin', methods=['POST', 'GET', 'OPTIONS'])
def login():
    if request.method == 'POST':
    	client = pymongo.MongoClient(mongoPath)
    	db = client.get_database('myDB')
    	records = db.users
    	username = request.get_json()['username']
    	password = request.get_json()['password']
    	result = ""
		
    	response = records.find_one({'username' : username})
	
    	if response:	
	        if bcrypt.check_password_hash(response['password'], password):
	            access_token = create_access_token(identity = {
				    'username': response['username']
	            })
	            result = jsonify({"token":access_token})
	        else:
	            result = jsonify({"error":"Invalid username and password"})            
    	else:
	        result = jsonify({"result":"No results found"})
    	return result
    return 'hello'+request.method

@app.after_request
def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', 'https://read-count.vercel.app')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
  response.headers.add('Access-Control-Allow-Credentials', 'true')
  return response
	
	
if __name__ == '__main__':
    app.run(host="0.0.0.0",threaded=True,port=portNumber or 8080)
