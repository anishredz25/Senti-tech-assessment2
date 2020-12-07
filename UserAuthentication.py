from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi
import hashlib
import hmac
from datetime import datetime, timedelta
import json
import base64

APPLICATION_KEY = "abcdefgh"
APPLICATION_SECRET = "12345678"

TOKEN_LIFETIME_HOURS = 1

PORT_NUMBER = 1234

# Test user database
# If done properly, would query a SQL database to get users
user_db = \
    [
        ("abc", hashlib.sha256("123".encode()+"abc".encode()).hexdigest(), "123"),
        ("admin", hashlib.sha256("456".encode()+"admin".encode()).hexdigest(), "456")
    ]

# define invalid credentials exception
class InvalidCredentialsException(Exception):
    pass

class AuthenticationHandler(BaseHTTPRequestHandler):


    def do_GET(self):
        """ handle page requests """

        if self.path.endswith("/"):

            # send response OK
            self.send_response(200)
            self.send_header("Content-type", "text-html")
            self.end_headers()

            # make test login form
            output = ""
            output += "<html><body>"
            output += "<form method='POST' enctype='multipart/form-data' action='/login'>"
            output += "<label for='user'>Username:</label><br>"
            output += "<input name='user' type='text'><br>"
            output += "<label for='password'>Password:</label><br>"
            output += "<input name='password' type='password'><br><br>"
            output += "<input type='submit' value='submit'>"
            output += "</form></body></html>"
            self.wfile.write(output.encode())
        else:
            # error handling
            self.send_error(404, 'File Not Found: %s' % self.path)


    def do_POST(self):
        """ handle form submission """

        # boilerplate code to get form user inputs
        content_type, param_dict =  cgi.parse_header(self.headers.get('Content-Type'))
        param_dict['boundary'] = bytes(param_dict['boundary'], "utf-8")
        content_len = int(self.headers.get('Content-length'))
        param_dict['CONTENT-LENGTH'] = content_len

        if content_type == 'multipart/form-data':


            payload = cgi.parse_multipart(self.rfile, param_dict)

            # get user inputs
            form_user = payload.get('user')[0]
            form_password = payload.get('password')[0]

            headers = []

            try:
                # check if user in database
                user_record = self.get_user(form_user)

                # if not in database raise exception
                if user_record is None:
                    raise InvalidCredentialsException

                true_hashed_password = user_record[1]
                salt = user_record[2]

                # compare hashed+salted user input to stored password
                if true_hashed_password != (hashlib.sha256(
                        salt.encode()+form_password.encode()).hexdigest()):

                    # if they do not match raise exception
                    raise InvalidCredentialsException

                #create token
                token = self.generate_token(
                    type="auth",
                    key = APPLICATION_KEY,
                    identity = user_record[0],
                    expiration_time = (datetime.now() +
                                       timedelta(
                                           hours=TOKEN_LIFETIME_HOURS)).strftime("%a, %d %b %Y %H:%M:%S GMT")
                )

                #set response as OK
                response_code = 200
                message = "Login Sucessful, Welcome {}".format(user_record[0])
                status = "Success"

                headers.append(token)

            except InvalidCredentialsException:
                # set response as unauthorized access
                response_code = 401
                message = "Invalid Credentials"
                status = "Failed"

            except Exception as e:
                # set response as internal server error
                print(e)
                response_code = 500
                message = "Internal Server Error"
                status = "Failed"

            finally:
                # write to client webpage
                headers.append(("Content-type", "application/json"))
                self.send_response(response_code)
                for header in headers:
                    self.send_header(header[0], header[1])
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"message": message, "status":status}), 'utf-8'))


    def get_user(self, username):
        """ look for user record, return empty if user not in database"""
        for users in user_db:
            print(users[0], username)
            if users[0] == username:
                return users

        return None

    def generate_token(self, type, key, identity, expiration_time):
        """ generate login token """

        #encode token data as base64
        token = {"type": type, "identity":identity, "key":key, "expiration":expiration_time}
        token_json = json.dumps(token).replace(" ", "")
        base64_token = base64.b64encode(bytes(token_json, "utf-8"))

        #token encrypted and sent to client
        digest = hmac.new(base64.b64decode(
            APPLICATION_SECRET), msg=base64_token, digestmod=hashlib.sha256).digest()
        signature = base64_token + b":" + base64.b64encode(digest)
        return ("Login-Token", signature)



httpd = HTTPServer(('localhost', PORT_NUMBER), AuthenticationHandler)
print('started httpserver on port {}'.format(PORT_NUMBER))

httpd.serve_forever()


