
from json import load, dump
from flask import Flask, request, abort, jsonify, make_response, render_template
from flask_cors import CORS
from better_profanity import profanity
import requests



app = Flask(__name__)
app.CORS = CORS(app, resources=r'*')

usernames_and_ips = {}

def save_db():
    with open("db.json", "w") as db:
        dump({"banned_ips": app.BANNED_IPS, "users": app.USERS, "reports": app.REPORTS}, db, indent=4)

def get_remote_adress(request):
    if "X-Forwarded-For" in request.headers:
        return request.headers["X-Forwarded-For"].split(",")[-1]
    return request.access_route[-1]

@app.before_request
def block_ips():
    if not request.method == "POST": return

    ip = get_remote_adress(request)

    post_data = request.get_json()

    if post_data is None:
        abort(jsonify({"Error":"empty", "message":"no json found"}),400)

    if profanity.contains_profanity(post_data.get("username", "")):
        abort(jsonify({"Error":"username_profanity_error", "message":"Username contains profanity"}),403)


    if "username" not in post_data and ip not in app.USERS:
        app.USERS[str(ip)] = len(app.USERS)
        save_db()

    post_data["username"] = post_data.get(
        "username", "guest" + str(app.USERS[str(ip)])
    ).replace(" ", "_")


    if app.meower.DISABLE_GUESTS and post_data['username'].startswith("guest"):
        abort(jsonify({"Error":"guests_app.meower.disabled"}),400)

    if not "post" in post_data:
        abort(jsonify({"Error":"missing", "key":"post"}),400)

    usernames_and_ips[post_data["username"]] = {"ip": ip, "pfp": post_data.get("pfp", 0)}


    if ip in app.BANNED_IPS or post_data.get("username") in app.BANNED_IPS:
        abort(jsonify({"Error":"banned"}),403)  # Ip is banned from The API for this meower bot

    request.ip = ip


@app.route("/")
def root():
    return render_template('index.html')

@app.route("/pfps/<username>")
def get_pfp(username):
    if username not in usernames_and_ips:
        return username, 404
    
    return usernames_and_ips[username]['pfp']

def post_to_chat(chat, data):
    app.meower.send_msg(f"{data['username']}: {data['post']}", to=chat)
	


@app.route("/post/<chat>", methods=["POST"])
def post(chat):

    post_data = request.get_json()
    post_to_chat(chat, post_data)
    return "", 204

# reporting
@app.route("/report/<message_id>", methods=["POST"])
def report(message_id):
    print(request.headers)
    # get the message from Meower, using the message id
    r = requests.get(f"https://api.meower.org/posts?id={message_id}")
    if r.status_code != 200:
        print(r.json())
        abort( r.json(), r.status_code)
    
    # get the message data
    message = r.json()

    data = {}
    


    # check if the message is from the bot
    if message["u"] != app.meower.username:
        return {"error": True, "message": "not from webhooks"}, 400

    data["message"] = message["p"].split(": ", 1)[1]
    data["username"] = message["p"].split(": ", 1)[0]

    # get the ip of the user
    ip = usernames_and_ips[data["username"]]["ip"]

    data["ip"] = ip # so we can IP ban them
    
    # get the user profile if it exists
    user_profile = app.USERS.get(ip, None)

    data['profile'] = user_profile

    # add the data to reports
    app.REPORTS.append(data)
    save_db()

    return "", 204


@app.route("/reports")
def get_reports():
    # super secret admin panel, that meower admins can use to see reports

    # check if the user is an admin
    autherization = request.headers.get("Authorization", None)
    username = request.headers.get("Username", None)

    if autherization is None or username is None:
        abort({"error": True, "message": "no autherization"}, 401)

    if username not in app.known_tokens:
        abort( {"error": True, "message": "unknown username"}, 401)

    if app.known_tokens[username]['token'] != autherization:
        abort(  {"error": True, "message": "invalid token"}, 401 )

    if not app.known_tokens[username]['level'] >= 2 and not username == "ShowierData9978":
        abort(  {"error": True, "message": "not an admin"}, 403 )
    


    # omit the ip from the reports
    reports = []
    for report in app.REPORTS:
        reports.append({k: v for k, v in report.items() if k != "ip"})

    return {"reports": reports}, 200

@app.route("/ban/ip/<ip>", methods=["POST"])
def ban_ip(ip):
    # super secret admin panel, that meower admins can use to ban ips

    # check if the user is an admin
    autherization = request.headers.get("Authorization", None)
    username = request.headers.get("Username", None)

    if autherization is None or username is None:
        abort(  {"error": True, "message": "no autherization"}, 401 )
    
    if username not in app.known_tokens:
        abort(  {"error": True, "message": "unknown username"}, 401 )

    if app.known_tokens[username]['token'] != autherization:
        abort(  {"error": True, "message": "invalid token"}, 401 )
    
    if not app.known_tokens[username]['level'] >= 3 and not username == "ShowierData9978":
        abort(  {"error": True, "message": "not an admin"}, 403 )

    # ban the ip
    app.BANNED_IPS.append(ip)
    save_db()

    return "", 204

@app.route("/ban/username/<username>", methods=["POST"])
def ban_username(username):
    # super secret admin panel, that meower admins can use to ban usernames

    # check if the user is an admin
    autherization = request.headers.get("Authorization", None)
    username = request.headers.get("Username", None)

    if autherization is None or username is None:
        return {"error": True, "message": "no autherization"}, 401
    
    if username not in app.known_tokens:
        return {"error": True, "message": "unknown username"}, 401

    if app.known_tokens[username]['token'] != autherization:
        return {"error": True, "message": "invalid token"}, 401

    if not app.known_tokens[username]['level'] >= 2 and not username == "ShowierData9978":
        return {"error": True, "message": "not an admin"}, 403

    # ban the username
    app.BANNED_IPS.append(username)
    save_db()

    return "", 204

@app.route("/reports", methods=["DELETE"])
def delete_reports():
    # super secret admin panel, that meower admins can use to delete reports

    # check if the user is an admin
    autherization = request.headers.get("Authorization", None)
    username = request.headers.get("Username", None)

    if autherization is None or username is None:
        return {"error": True, "message": "no autherization"}, 401
    
    if username not in app.known_tokens:
        return {"error": True, "message": "unknown username"}, 401

    if app.known_tokens[username]['token'] != autherization:
        return {"error": True, "message": "invalid token"}, 401
    
    if not app.known_tokens[username]['level'] >= 2 and not username == "ShowierData9978":
        return {"error": True, "message": "not an admin"}, 403
    
    # get the index of the report to delete
    index = request.args.get("index", 0)

    try:
        index = int(index)
    except ValueError:
        return {"error": True, "message": "invalid index"}, 400

    # delete the report
    del app.REPORTS[index]
    save_db()

    return "", 204




@app.after_request
def after_request_func(response):
        origin = request.headers.get('Origin')
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
            response.headers.add('Access-Control-Allow-Headers', 'x-csrf-token')
            response.headers.add('Access-Control-Allow-Methods',
                                'GET, POST, OPTIONS, PUT, PATCH, DELETE')
            if origin:
                response.headers.add('Access-Control-Allow-Origin', origin)
        else:
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            if origin:
                response.headers.add('Access-Control-Allow-Origin', origin)

        return response


if __name__ == "__main__":
    raise ImportError("web.py should be a module, not a main file")
