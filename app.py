from flask import Flask, render_template, request, session, jsonify
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import ibm_db
from flask_cors import CORS

import bcrypt
app = Flask(__name__)
CORS(app)
# conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=125f9f61-9715-46f9-9399-c8177b21803b.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT=30426;UID=spv26617;PWD=P3FX7zyl2lsmzJHe;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt",'','')
conn = ibm_db.connect("database=bludb;hostname=b70af05b-76e4-4bca-a1f5-23dbb4c6a74e.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;port=32716;uid=nxl07317;pwd=42V4zM6ZGeH7sWfR;security=SSL;sslcertificate=DigiCertGlobalRootCA.crt"," "," ")
print(conn)
connState = ibm_db.active(conn)
print("This","_",connState)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/' #here you can give any random bytes



# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "firstform-thunderbreathing"  # Change this!
jwt = JWTManager(app)


# @app.route('/token',methods=['POST'])
# def create_token():
#     email = request.json.get("email",None)
#     password = request.json.get("password",None)
#     if email != "test" or password != "test":
#         return jsonify({"msg":"Bad Username or password"}),401
    
#     access_token = create_access_token(identity=email)
#     return jsonify(access_token=access_token)

@app.route("/", methods = ['POST'])
def login():
    global uemail
    email = request.json.get("email", None)
    password =  request.json.get("password", None)
    details = [email, password]
    print(details)
    hashed = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
    print ("hashed",hashed)
    sql = "SELECT * FROM REGISTER_HC where EMAILID=? AND PASSWORD = ?"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt, 1, email)
    ibm_db.bind_param(stmt, 2, password)
    ibm_db.execute(stmt)
    acc = ibm_db.fetch_assoc(stmt)
    print("acc",acc)
    if acc:
        name = acc.get('NAME')
        print(name)
        access_token=create_access_token(identity={"email":email, "name": name})
        return {"access_token": access_token},200
    else:
        return 'Invalid Login Info !',400
    
# @app.route("/test", methods = ['POST'])
# def test():


# @app.route("/profile")
# def profile():
#     return render_template("profile.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        print('working1')
        name = request.json.get('name')
        email = request.json.get('email')
        password = request.json.get('password')
        role = request.json.get('role')
        details = [name,email,password,role]
        print(details)
        sql = "SELECT * FROM REGISTER_HC where EMAILID=?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, email)
        # ibm_db.bind_param(stmt, 2, name)
        ibm_db.execute(stmt)
        acc = ibm_db.fetch_assoc(stmt)
        print("41","_",acc)
        if acc:
            response = {
                "message": "You have been already REGISTERED, please login!"
            }
        else:
            sql = "INSERT into REGISTER_HC VALUES (?,?,?,?)"
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, name)
            ibm_db.bind_param(stmt, 2, email)
            ibm_db.bind_param(stmt, 3, password)
            ibm_db.bind_param(stmt, 4, role)
            ibm_db.execute(stmt)
            response = {
                "message": "You have Successfully REGISTERED, Please LOGIN"
            }

        return jsonify(response)

# @app.route("/logout")
# def logout():
#     session.pop("email", None)
#     session.pop("username", None)
#     return render_template("index.html")




if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)
