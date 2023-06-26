# Store this code in 'app.py' file
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import spacy
from spacy import displacy
import requests
import tensorflow as tf
from keras.utils import pad_sequences
import re
import pickle
import numpy as np

def clean_text(text):
    text = re.sub(r"[^a-zA-Z ]", "", text)
    text = text.lower()
    return text

app = Flask(__name__, template_folder='')

app.secret_key = secrets.token_hex(16)
# app.debug = True

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'ner'
app.config['TEMPLATES_AUTO_RELOAD'] = True

mysql = MySQL(app)

@app.route('/')
def index():
	if not session:
		session['loggedin'] = False
	if session['loggedin']:
		return render_template('index.html', name=session['name'])
	else:
		return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	if not session['loggedin']:
		msg = ''
		if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
			email = request.form['email']
			password = request.form['password']
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute('SELECT * FROM users WHERE email = %s', (email, ))
			account = cursor.fetchone()
			if account and check_password_hash(account['password'], password):
				session['loggedin'] = True
				session['id'] = account['id']
				session['email'] = account['email']
				session['name'] = account['name']
				msg = 'Logged in successfully !'
				return redirect(url_for('index'))
			else:
				msg = 'Incorrect username / password !'
		return render_template('login.html', msg=msg)
	else:
		return redirect(url_for('index'))


@app.route('/logout', methods=['POST'])
def logout():
    session['loggedin'] = False
    session.pop('id', None)
    session.pop('email', None)
    session.pop('name', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
	if not session['loggedin']:
		msg = ''
		if request.method == 'POST' and 'name' in request.form and 'email' in request.form and 'password' in request.form and 'confirm_password' in request.form:
			name = request.form['name']
			email = request.form['email']
			password = request.form['password']
			confirm_password = request.form['confirm_password']
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
			account = cursor.fetchone()
			if account:
				msg = 'Account already exists !'
				return render_template('register.html', msg=msg)
			elif not name or not email or not password or not confirm_password:
				msg = 'Please fill out the entire form !'
				return render_template('register.html', msg=msg)
			elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
				msg = 'Invalid email address !'
				return render_template('register.html', msg=msg)
			elif password != confirm_password:
				msg = 'Password not matched !'
				return render_template('register.html', msg=msg)
			else:
				cursor.execute('INSERT INTO users (name, email, password) VALUES (%s, %s, %s)', (name, email, generate_password_hash(password)))
				mysql.connection.commit()
				msg = 'You have successfully registered !'
				session['loggedin'] = True
				session['id'] = account['id']
				session['email'] = account['email']
				session['name'] = account['name']
				return redirect(url_for('index'))
		else:
			return render_template('register.html', msg='')
	else:
		return redirect(url_for('index'))


@app.route("/processMessage/<query>/<m>", methods=['GET', 'POST'])
def processMessage(query, m):
	disease = ''
	with open("word2idx.pkl", "rb") as file:
		word2idx = pickle.load(file)

	model = tf.keras.models.load_model("ner_lstm")
	query = clean_text(query)
	words = query.split()
	num_words = len(word2idx)
	indices = [word2idx.get(word, 0) for word in words]
	padded = pad_sequences([indices], maxlen=50, padding="post", value=num_words-1)
	# print(padded)
	prediction = model.predict(padded)
	predicted_labels = np.argmax(prediction, axis=-1)[0]  # Get predicted labels for the first example
	# print(predicted_labels)
	for i in range(len(words)):
		# print(predicted_labels[i])
		if predicted_labels[i] == 1:
			disease += words[i] + ' '
		# disease += predicted_labels[i]

	if disease:
		url = 'https://api.pawan.krd/v1/chat/completions'
		headers = {
			'Authorization': 'pk-oCIWFYSLeLLdpIUhArNpocaywVDoFfMOoESgIkZiuqCjEvJP',
			'Content-Type': 'application/json',
		}
		data = {
			"model": "gpt-3.5-turbo",
			"max_tokens": 500,
			"messages": [
				{
					"role": "system",
					"content": "You are an helpful assistant."
				},
				{
					"role": "user",
					"content": f"Hi, I have been feeling unwell and experiencing some symptoms such as {disease}. Can you please suggest some medications for the possible diseases that could be causing these symptoms. Also suggest some precautions and further dangers if I avoid it."
				}
			]
		}

		response = requests.post(url, headers=headers, json=data)

		output = ''
		try:
			output = response.json()['choices'][0]['message']['content']
		except:
			output = response.json()
	else:
		output = 'Sorry, I could not understand your query. Please try again.'

	result = {'response': output, 'disease': disease}
	# print(result)
	return result

	# return model + '-' + disease

@app.route("/addNewChat/<chatName>", methods=['GET', 'POST'])
def addNewChat(chatName):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('INSERT into chats (user_id, name) VALUES (%s, %s)', (session['id'],chatName))
	mysql.connection.commit()
	cursor.execute('SELECT * FROM chats WHERE id=%s', (cursor.lastrowid,))
	data = cursor.fetchone()
	return data
	# return str(cursor.lastrowid)

@app.route("/addNewMessage/<chatId>/<query>/<response>", methods=['GET', 'POST'])
def addNewMessage(chatId, query, response):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('INSERT into messages (chat_id, question, answer) VALUES (%s, %s, %s)', (chatId, query, response))
	mysql.connection.commit()
	return 'success'

@app.route("/getChats", methods=['GET', 'POST'])
def getChats():
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM chats WHERE user_id = %s ORDER BY id DESC', (session['id'],))
	chats = cursor.fetchall()
	return list(chats)

@app.route("/getMessages/<chatId>", methods=['GET', 'POST'])
def getMessages(chatId):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('SELECT * FROM messages WHERE chat_id = %s', (chatId,))
	messages = cursor.fetchall()
	return list(messages)

@app.route("/deleteChat/<chatId>", methods=['GET', 'POST'])
def deleteChat(chatId):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute('DELETE FROM chats WHERE id = %s', (chatId,))
	cursor.execute('DELETE FROM messages WHERE chat_id = %s', (chatId,))
	mysql.connection.commit()
	return 'success'

# @app.route("/display")
# def display():
# 	if 'loggedin' in session:
# 		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 		cursor.execute('SELECT * FROM accounts WHERE id = % s',
# 					(session['id'], ))
# 		account = cursor.fetchone()
# 		return render_template("display.html", account=account)
# 	return redirect(url_for('login'))


# @app.route("/update", methods=['GET', 'POST'])
# def update():
# 	msg = ''
# 	if 'loggedin' in session:
# 		if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'address' in request.form and 'city' in request.form and 'country' in request.form and 'postalcode' in request.form and 'organisation' in request.form:
# 			username = request.form['username']
# 			password = request.form['password']
# 			email = request.form['email']
# 			organisation = request.form['organisation']
# 			address = request.form['address']
# 			city = request.form['city']
# 			state = request.form['state']
# 			country = request.form['country']
# 			postalcode = request.form['postalcode']
# 			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
# 			cursor.execute(
# 				'SELECT * FROM accounts WHERE username = % s',
# 					(username, ))
# 			account = cursor.fetchone()
# 			if account:
# 				msg = 'Account already exists !'
# 			elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
# 				msg = 'Invalid email address !'
# 			elif not re.match(r'[A-Za-z0-9]+', username):
# 				msg = 'name must contain only characters and numbers !'
# 			else:
# 				cursor.execute('UPDATE accounts SET username =% s,\
# 				password =% s, email =% s, organisation =% s, \
# 				address =% s, city =% s, state =% s, \
# 				country =% s, postalcode =% s WHERE id =% s', (
# 					username, password, email, organisation,
# 				address, city, state, country, postalcode,
# 				(session['id'], ), ))
# 				mysql.connection.commit()
# 				msg = 'You have successfully updated !'
# 		elif request.method == 'POST':
# 			msg = 'Please fill out the form !'
# 		return render_template("update.html", msg=msg)
# 	return redirect(url_for('login'))


if __name__ == "__main__":
	app.run(host="localhost", port=int("5000"), debug=True)
